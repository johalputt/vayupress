// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"time"

	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/queue"
	"github.com/johalputt/vayupress/internal/trace"
)

// ArticleService owns all business logic for article CRUD. Handlers call
// service methods; the service owns validation, quota checks, and queue dispatch.
// Persistence is delegated to the injected ArticleRepository and queue.Writer.
type ArticleService struct {
	Repo           ArticleRepository
	Queue          queue.Writer
	StorageCheckFn func() (used, quota int64) // nil = skip quota check
}

// CreateResult is returned after a successful create operation.
type CreateResult struct {
	ID   string
	Slug string
}

// BulkResult is returned after a bulk create.
type BulkResult struct {
	Queued      int
	Skipped     int
	SkipReasons []string
}

// ListResult is the paginated article list response.
type ListResult struct {
	Articles []ArticleSummary
	Page     int
	Limit    int
	Total    int
	Pages    int
}

// ArticleSummary is the list-view projection of an article (no content).
type ArticleSummary struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Slug      string    `json:"slug"`
	Tags      []string  `json:"tags"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TagCount pairs a tag name with the number of articles using it.
type TagCount struct {
	Tag   string `json:"tag"`
	Count int    `json:"count"`
}

// BulkCreateItem is the input type for a single item in a bulk create.
type BulkCreateItem struct {
	Title, Slug, Content string
	Tags                 []string `json:"tags"`
}

// Create validates and enqueues a new blog post.
func (s *ArticleService) Create(ctx context.Context, title, slug, content string, tags []string) (CreateResult, error) {
	return s.create(ctx, title, slug, content, tags, false, "published")
}

// CreateDraft is the authoring-surface create: VayuOS's editor and quick-compose
// use it so a brand-new post is born a DRAFT and publishing stays a deliberate
// act (dashboard-upgrade Wave 1). The public API, MCP tools and the scheduler
// keep using Create — their published-by-default contract is unchanged.
func (s *ArticleService) CreateDraft(ctx context.Context, title, slug, content string, tags []string) (CreateResult, error) {
	return s.create(ctx, title, slug, content, tags, false, "draft")
}

// CreatePage validates and enqueues a new standalone page (is_page=1). It is
// identical to Create except the is_page flag flows through the insert atomically,
// so a page is never briefly published as a post before a follow-up UPDATE flips
// the flag (the race the old create-then-setArticleIsPage pattern carried).
func (s *ArticleService) CreatePage(ctx context.Context, title, slug, content string, tags []string) (CreateResult, error) {
	return s.create(ctx, title, slug, content, tags, true, "published")
}

// create is the shared post/page create path. isPage selects the article kind;
// status is persisted verbatim through the queue ("" would fall back to the
// schema default 'published' at write time, so callers always pass one).
func (s *ArticleService) create(ctx context.Context, title, slug, content string, tags []string, isPage bool, status string) (CreateResult, error) {
	ctx, span := trace.Start(ctx, "ArticleService.Create")
	defer span.End()
	// Auto-derive a slug from the title when the caller omits one (ADR-0047).
	if slug == "" {
		slug = Slugify(title)
	}
	span.SetAttribute("slug", slug)
	if isPage {
		span.SetAttribute("kind", "page")
	}
	if err := ValidateArticleInput(title, slug, content, tags); err != nil {
		span.SetError(err)
		return CreateResult{}, err
	}
	if s.StorageCheckFn != nil {
		used, quota := s.StorageCheckFn()
		if used >= quota {
			return CreateResult{}, ErrStorageQuota
		}
	}
	exists, err := s.Repo.SlugExists(ctx, slug)
	if err != nil {
		return CreateResult{}, err
	}
	if exists {
		return CreateResult{}, ErrSlugConflict
	}
	art := dbpkg.Article{
		ID: newID(), Title: title, Slug: slug,
		Content: content, Tags: tags, IsPage: isPage, Status: status,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := s.Queue.Enqueue(ctx, art, "insert"); err != nil {
		return CreateResult{}, fmt.Errorf("queue: %w", err)
	}
	return CreateResult{ID: art.ID, Slug: art.Slug}, nil
}

// ListPages returns up to limit standalone pages (newest-updated first) as
// summaries — the read behind the list_pages MCP tool. Pages are excluded from
// List (the blog feed), so they need their own listing.
func (s *ArticleService) ListPages(ctx context.Context, limit int) ([]ArticleSummary, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	pages, err := s.Repo.ListPages(ctx, limit)
	if err != nil {
		return nil, err
	}
	out := make([]ArticleSummary, 0, len(pages))
	for _, a := range pages {
		out = append(out, ArticleSummary{
			ID: a.ID, Title: a.Title, Slug: a.Slug, Tags: a.Tags,
			CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt,
		})
	}
	return out, nil
}

// BulkCreate creates multiple articles, skipping those that fail validation or
// have duplicate slugs. It follows the same rules as single Create: slugs are
// auto-derived from the title when omitted (ADR-0047), a duplicate-slug lookup
// failure is fail-closed rather than treated as "not a duplicate", and an
// enqueue failure counts the item as skipped — Queued must mean persisted.
func (s *ArticleService) BulkCreate(ctx context.Context, items []BulkCreateItem) (BulkResult, error) {
	if len(items) > 1000 {
		return BulkResult{}, ErrBulkLimit
	}
	res := BulkResult{}
	for _, in := range items {
		// Mirror Create's ADR-0047 derivation so the same logical payload is
		// not accepted once and skipped in bulk.
		if in.Slug == "" {
			in.Slug = Slugify(in.Title)
		}
		if err := ValidateArticleInput(in.Title, in.Slug, in.Content, in.Tags); err != nil {
			res.Skipped++
			res.SkipReasons = append(res.SkipReasons, in.Slug+": "+err.Error())
			continue
		}
		// Same storage-quota gate as Create: without it one bulk call — or a
		// stream of them — filled the database past its ceiling while every
		// single-article create was being refused (audit).
		if s.StorageCheckFn != nil {
			used, quota := s.StorageCheckFn()
			if used >= quota {
				res.Skipped++
				res.SkipReasons = append(res.SkipReasons, in.Slug+": storage quota exceeded")
				continue
			}
		}
		exists, err := s.Repo.SlugExists(ctx, in.Slug)
		if err != nil {
			// Unknown state: enqueueing anyway would defeat the guard and let
			// the item die invisibly against the UNIQUE constraint.
			res.Skipped++
			res.SkipReasons = append(res.SkipReasons, in.Slug+": slug lookup unavailable")
			continue
		}
		if exists {
			res.Skipped++
			res.SkipReasons = append(res.SkipReasons, in.Slug+": duplicate slug")
			continue
		}
		art := dbpkg.Article{
			ID: newID(), Title: in.Title, Slug: in.Slug,
			Content: in.Content, Tags: in.Tags,
			CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		}
		if err := s.Queue.Enqueue(ctx, art, "insert"); err != nil {
			res.Skipped++
			res.SkipReasons = append(res.SkipReasons, in.Slug+": enqueue failed ("+err.Error()+")")
			continue
		}
		res.Queued++
	}
	return res, nil
}

// Update fetches the article by slug, applies the partial update, and enqueues.
func (s *ArticleService) Update(ctx context.Context, slug string, title, content *string, tags []string) (dbpkg.Article, error) {
	ctx, span := trace.Start(ctx, "ArticleService.Update")
	defer span.End()
	span.SetAttribute("slug", slug)
	art, err := s.Repo.Get(ctx, slug)
	if err != nil {
		span.SetError(err)
		return art, mapRepoErr(err)
	}
	if title != nil {
		art.Title = *title
	}
	if content != nil {
		art.Content = *content
	}
	if tags != nil {
		art.Tags = tags
	}
	art.UpdatedAt = time.Now().UTC()
	// Enforce the same field limits as Create on the merged result (title ≤500,
	// content ≤5 MB, ≤20 tags each ≤100 chars). Without this an update could store
	// an oversized row that Create would reject — a hole reachable from both the
	// REST PUT and the MCP update_post tool. (Storage-quota is intentionally not
	// re-checked here: an update overwrites in place and must stay allowed even at
	// quota so an operator can shrink a post.)
	if err := ValidateArticleInput(art.Title, art.Slug, art.Content, art.Tags); err != nil {
		span.SetError(err)
		return art, err
	}
	if err := s.Queue.Enqueue(ctx, art, "update"); err != nil {
		return art, fmt.Errorf("queue: %w", err)
	}
	return art, nil
}

// Delete fetches the article by slug and enqueues a delete operation.
func (s *ArticleService) Delete(ctx context.Context, slug string) (dbpkg.Article, error) {
	ctx, span := trace.Start(ctx, "ArticleService.Delete")
	defer span.End()
	span.SetAttribute("slug", slug)
	art, err := s.Repo.Get(ctx, slug)
	if err != nil {
		span.SetError(err)
		return art, mapRepoErr(err)
	}
	if err := s.Queue.Enqueue(ctx, art, "delete"); err != nil {
		return art, fmt.Errorf("queue: %w", err)
	}
	return art, nil
}

// Get returns the article for the given slug.
func (s *ArticleService) Get(ctx context.Context, slug string) (dbpkg.Article, error) {
	ctx, span := trace.Start(ctx, "ArticleService.Get")
	defer span.End()
	span.SetAttribute("slug", slug)
	if !IsValidSlug(slug) {
		span.SetError(ErrInvalidSlug)
		return dbpkg.Article{}, ErrInvalidSlug
	}
	art, err := s.Repo.Get(ctx, slug)
	if err != nil {
		span.SetError(err)
	}
	return art, mapRepoErr(err)
}

// GetScoped is Get restricted to a VayuDomains scope so a secondary domain can
// only reach its own content (ADR-0132, Stage 2).
func (s *ArticleService) GetScoped(ctx context.Context, scope, slug string) (dbpkg.Article, error) {
	if !IsValidSlug(slug) {
		return dbpkg.Article{}, ErrInvalidSlug
	}
	art, err := s.Repo.GetScoped(ctx, scope, slug)
	return art, mapRepoErr(err)
}

// ListOwnedBy returns everything one domain owns — drafts and pages included —
// for that site's own console (ADR-0154 D4).
func (s *ArticleService) ListOwnedBy(ctx context.Context, domainID string, limit int) ([]dbpkg.Article, error) {
	return s.Repo.ListOwnedBy(ctx, domainID, limit)
}

// SetDomain reassigns an article to a domain ("" = the primary domain).
func (s *ArticleService) SetDomain(ctx context.Context, slug, domainID string) error {
	if !IsValidSlug(slug) {
		return ErrInvalidSlug
	}
	return mapRepoErr(s.Repo.SetDomain(ctx, slug, domainID))
}

// CountsByDomain returns the number of articles owned by each domain id.
func (s *ArticleService) CountsByDomain(ctx context.Context) (map[string]int, error) {
	return s.Repo.CountsByDomain(ctx)
}

// ListScoped is List restricted to a VayuDomains scope.
func (s *ArticleService) ListScoped(ctx context.Context, scope string, page, limit int, tag string) (ListResult, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	articles, total, err := s.Repo.ListScoped(ctx, scope, page, limit, tag)
	if err != nil {
		return ListResult{}, err
	}
	summaries := make([]ArticleSummary, 0, len(articles))
	for _, a := range articles {
		summaries = append(summaries, ArticleSummary{
			ID: a.ID, Title: a.Title, Slug: a.Slug, Tags: a.Tags,
			CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt,
		})
	}
	pages := (total + limit - 1) / limit
	return ListResult{Articles: summaries, Page: page, Limit: limit, Total: total, Pages: pages}, nil
}

// List returns a paginated, optionally tag-filtered, article summary list.
func (s *ArticleService) List(ctx context.Context, page, limit int, tag string) (ListResult, error) {
	ctx, span := trace.Start(ctx, "ArticleService.List")
	defer span.End()
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	articles, total, err := s.Repo.List(ctx, page, limit, tag)
	if err != nil {
		return ListResult{}, err
	}
	summaries := make([]ArticleSummary, 0, len(articles))
	for _, a := range articles {
		summaries = append(summaries, ArticleSummary{
			ID: a.ID, Title: a.Title, Slug: a.Slug, Tags: a.Tags,
			CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt,
		})
	}
	pages := (total + limit - 1) / limit
	return ListResult{Articles: summaries, Page: page, Limit: limit, Total: total, Pages: pages}, nil
}

// ListTags returns all distinct tag names with counts across all articles.
func (s *ArticleService) ListTags(ctx context.Context) ([]TagCount, error) {
	tagCount, err := s.Repo.TagCounts(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]TagCount, 0, len(tagCount))
	for t, c := range tagCount {
		result = append(result, TagCount{Tag: t, Count: c})
	}
	return result, nil
}

// mapRepoErr translates db-level sentinel errors to api-level sentinels so
// handlers always work with api.Err* values.
func mapRepoErr(err error) error {
	if err == nil {
		return nil
	}
	if err == dbpkg.ErrNotFound {
		return ErrNotFound
	}
	return err
}
