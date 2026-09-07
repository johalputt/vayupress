// SPDX-License-Identifier: Apache-2.0

// Package queue manages the async write queue, dead-letter handling, replay safety,
// and poison job quarantine (ADR-0035).
package queue

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/johalputt/vayupress/internal/config"
	dbpkg "github.com/johalputt/vayupress/internal/db"
	"github.com/johalputt/vayupress/internal/events"
	"github.com/johalputt/vayupress/internal/logging"
	"github.com/johalputt/vayupress/internal/metrics"
)

// WriteJob is a pending DB mutation stored in the write_jobs table.
type WriteJob struct {
	ID            int64
	ArticleJSON   string
	Op            string
	CorrelationID string
}

// DoneCh signals workers to drain and exit on graceful shutdown.
var DoneCh = make(chan struct{})

// RenderFn is injected by main to break the queue→render import cycle.
var RenderFn func(dbpkg.Article) (string, error)

// EventBus is injected by main. Workers publish typed domain events after
// successful DB mutations; subscribers handle indexing, caching, and plugins.
var EventBus *events.Bus

const maxBackoffSeconds = 300

// StartWorkerPool launches cfg.WorkerCount write-queue workers.
func StartWorkerPool(wg *sync.WaitGroup) {
	for i := 0; i < config.Cfg.WorkerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			atomic.AddInt64(&metrics.WorkerLiveness, 1)
			defer atomic.AddInt64(&metrics.WorkerLiveness, -1)
			metrics.WorkerLastActivity.Store(workerID, time.Now())
			logging.LogInfo("worker", fmt.Sprintf("worker-%d started", workerID))
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-DoneCh:
					logging.LogInfo("worker", fmt.Sprintf("worker-%d draining", workerID))
					for !processOneJob(workerID) {
					}
					logging.LogInfo("worker", fmt.Sprintf("worker-%d done", workerID))
					return
				case <-ticker.C:
					processOneJob(workerID)
				}
			}
		}(i)
	}
}

func processOneJob(workerID int) (empty bool) {
	if config.Cfg.MaintenanceMode {
		return true
	}
	var job WriteJob
	err := dbpkg.DB.QueryRow(`SELECT id,article_json,op,correlation_id FROM write_jobs WHERE status='pending' AND (retry_at IS NULL OR retry_at <= datetime('now')) ORDER BY created_at ASC LIMIT 1`).Scan(&job.ID, &job.ArticleJSON, &job.Op, &job.CorrelationID)
	if err != nil {
		return true
	}
	// Best-effort status transitions throughout this worker: failures are
	// self-healing via StartStuckJobReaper (resets stale 'processing' rows) and
	// the retry/backoff path below, so they are intentionally not error-checked.
	_, _ = dbpkg.WDB.Exec(`UPDATE write_jobs SET status='processing' WHERE id=?`, job.ID)
	jobStart := time.Now()
	var a dbpkg.Article
	if err := json.Unmarshal([]byte(job.ArticleJSON), &a); err != nil {
		logging.LogError("worker", fmt.Sprintf("worker-%d bad JSON job %d", workerID, job.ID), err.Error())
		_, _ = dbpkg.WDB.Exec(`UPDATE write_jobs SET status='dead_letter',dead_reason='parse_error' WHERE id=?`, job.ID)
		return false
	}
	var execErr error
	switch job.Op {
	case "insert":
		execErr = dbpkg.RunInTx(context.Background(), dbpkg.DB, func(tx *sql.Tx) error {
			// Persist the article's own status. Jobs enqueued before status
			// travelled through the queue (or callers leaving it empty) keep the
			// historical schema default 'published'; authoring surfaces pass
			// "draft" explicitly (dashboard-upgrade Wave 1).
			status := strings.TrimSpace(a.Status)
			if status == "" {
				status = "published"
			}
			if _, err := tx.Exec(`INSERT INTO articles(id,title,slug,content,tags,created_at,updated_at,is_page,status) VALUES(?,?,?,?,?,?,?,?,?)`,
				a.ID, a.Title, a.Slug, a.Content, strings.Join(a.Tags, ","), a.CreatedAt, a.UpdatedAt, boolToInt(a.IsPage), status); err != nil {
				return err
			}
			// Keep the indexed tag-membership table in sync within the same tx.
			if err := dbpkg.SyncArticleTagsByIDTx(tx, a.ID, a.CreatedAt, a.Tags); err != nil {
				return err
			}
			if err := writeOutboxEvent(tx, "article.created.v1", events.ArticleCreated{ID: a.ID, Slug: a.Slug, Tags: a.Tags}, fmt.Sprintf("%d", job.ID), job.CorrelationID); err != nil {
				return err
			}
			return writeOutboxEvent(tx, "cache.invalidated.v1", events.CacheInvalidated{Slug: a.Slug, Tags: a.Tags, Reason: "insert"}, fmt.Sprintf("%d", job.ID), job.CorrelationID)
		})
		if execErr == nil {
			atomic.AddInt64(&metrics.MetricArticlesCreated, 1)
		}
	case "update":
		execErr = dbpkg.RunInTx(context.Background(), dbpkg.DB, func(tx *sql.Tx) error {
			// Snapshot the row we are about to overwrite so the editor's History
			// modal has real data (dashboard-upgrade Wave 1: versions were dead
			// plumbing — nothing ever wrote one). Best-effort: a snapshot failure
			// must never block the update itself.
			var vID, vTitle, vContent, vTags string
			if err := tx.QueryRow(`SELECT id,title,content,COALESCE(tags,'') FROM articles WHERE slug=?`, a.Slug).Scan(&vID, &vTitle, &vContent, &vTags); err == nil {
				if _, err := tx.Exec(`INSERT INTO article_versions(article_id,slug,title,content,tags,label) VALUES(?,?,?,?,?,?)`,
					vID, a.Slug, vTitle, vContent, vTags, "pre-update"); err != nil {
					logging.LogError("worker", "version snapshot failed for "+a.Slug, err.Error())
				}
			} else if err != sql.ErrNoRows {
				logging.LogError("worker", "version snapshot read failed for "+a.Slug, err.Error())
			}
			if _, err := tx.Exec(`UPDATE articles SET title=?,content=?,tags=?,updated_at=? WHERE slug=?`,
				a.Title, a.Content, strings.Join(a.Tags, ","), a.UpdatedAt, a.Slug); err != nil {
				return err
			}
			// Resolve the id by slug inside the tx and rewrite its tag membership.
			if err := dbpkg.SyncArticleTagsBySlugTx(tx, a.Slug, a.Tags); err != nil {
				return err
			}
			if err := writeOutboxEvent(tx, "article.updated.v1", events.ArticleUpdated{ID: a.ID, Slug: a.Slug, Tags: a.Tags}, fmt.Sprintf("%d", job.ID), job.CorrelationID); err != nil {
				return err
			}
			return writeOutboxEvent(tx, "cache.invalidated.v1", events.CacheInvalidated{Slug: a.Slug, Tags: a.Tags, Reason: "update"}, fmt.Sprintf("%d", job.ID), job.CorrelationID)
		})
		if execErr == nil {
			atomic.AddInt64(&metrics.MetricArticlesUpdated, 1)
		}
	case "delete":
		execErr = dbpkg.RunInTx(context.Background(), dbpkg.DB, func(tx *sql.Tx) error {
			// Remove tag membership before the row disappears (slug must still resolve).
			if err := dbpkg.DeleteArticleTagsBySlugTx(tx, a.Slug); err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM articles WHERE slug=?`, a.Slug); err != nil {
				return err
			}
			if err := writeOutboxEvent(tx, "article.deleted.v1", events.ArticleDeleted{ID: a.ID, Slug: a.Slug}, fmt.Sprintf("%d", job.ID), job.CorrelationID); err != nil {
				return err
			}
			return writeOutboxEvent(tx, "cache.invalidated.v1", events.CacheInvalidated{Slug: a.Slug, Tags: a.Tags, Reason: "delete"}, fmt.Sprintf("%d", job.ID), job.CorrelationID)
		})
		if execErr == nil {
			atomic.AddInt64(&metrics.MetricArticlesDeleted, 1)
		}
	default:
		_, _ = dbpkg.WDB.Exec(`UPDATE write_jobs SET status='dead_letter',dead_reason='unknown_op' WHERE id=?`, job.ID)
		return false
	}
	if execErr != nil {
		var retries int
		dbpkg.DB.QueryRow(`SELECT retries FROM write_jobs WHERE id=?`, job.ID).Scan(&retries)
		if retries < 3 {
			backoffSeconds := int(math.Pow(2, float64(retries+1))) * 5
			if backoffSeconds > maxBackoffSeconds {
				backoffSeconds = maxBackoffSeconds
			}
			nextRetry := time.Now().Add(time.Duration(backoffSeconds) * time.Second).UTC().Format("2006-01-02T15:04:05Z")
			_, _ = dbpkg.WDB.Exec(`UPDATE write_jobs SET status='pending',retries=retries+1,retry_at=? WHERE id=?`, nextRetry, job.ID)
		} else {
			_, _ = dbpkg.WDB.Exec(`UPDATE write_jobs SET status='dead_letter',dead_reason='max_retries' WHERE id=?`, job.ID)
			atomic.AddInt64(&metrics.MetricQueueFailed, 1)
			atomic.AddInt64(&metrics.MetricDeadLetterJobs, 1)
		}
		return false
	}
	if job.Op != "delete" && RenderFn != nil {
		// Never write a draft's HTML to the public disk cache — the article page
		// serves the cache file before its status check, so a cached draft would
		// be publicly readable. Read the authoritative status AND is_page of the row
		// we just wrote.
		var status string
		var isPage int
		if err := dbpkg.DB.QueryRow(`SELECT COALESCE(status,'published'), COALESCE(is_page,0) FROM articles WHERE slug=?`, a.Slug).Scan(&status, &isPage); err != nil {
			status, isPage = "published", 0 // row missing/unknown — fall back to prior behaviour
		}
		// Pre-seed the disk cache only for published BLOG POSTS. Pages (is_page=1)
		// are intentionally skipped: RenderFn renders with post chrome (published
		// date, tags, related, comments, author box), which is wrong for a page, so
		// a pre-seeded page cache would serve the page as a post until it is purged.
		// Pages are few and the live article handler renders them correctly on demand
		// (it reads is_page), so skipping the pre-seed is both correct and cheap.
		if status == "published" && isPage == 0 {
			html, err := RenderFn(a)
			if err != nil {
				logging.LogError("worker", "render error for "+a.Slug, err.Error())
			} else {
				cacheWriteFn(fmt.Sprintf("posts/%s.html", a.Slug), html)
			}
		}
	}
	_, _ = dbpkg.DB.Exec(`UPDATE write_jobs SET status='completed' WHERE id=?`, job.ID)
	atomic.AddInt64(&metrics.MetricQueueProcessed, 1)
	metrics.QueueJobLatency.Record(time.Since(jobStart))
	var qDepth int
	dbpkg.DB.QueryRow(`SELECT COUNT(1) FROM write_jobs WHERE status='pending'`).Scan(&qDepth)
	if qDepth > config.Cfg.QueueSaturationWarn {
		logging.LogJSON(logging.LogFields{Level: "warn", Component: "queue", Msg: fmt.Sprintf("saturation: %d pending", qDepth)})
	}
	metrics.WorkerLastActivity.Store(workerID, time.Now())
	return false
}

// CacheWriteFn is injected by main to write rendered articles to the cache directory.
var cacheWriteFn func(relPath, content string)

// SetCacheWriteFn sets the cache write function (called from main.go).
func SetCacheWriteFn(fn func(relPath, content string)) { cacheWriteFn = fn }

// newEventID returns a cryptographically random 32-character hex string.
func newEventID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// writeOutboxEvent wraps event in an Envelope and inserts it into event_outbox within tx.
func writeOutboxEvent(tx *sql.Tx, eventType string, event interface{}, causationID, correlationID string) error {
	inner, err := json.Marshal(event)
	if err != nil {
		return err
	}
	env := events.Envelope{
		EventID:       newEventID(),
		EventType:     eventType,
		EventVersion:  "1",
		CausationID:   causationID,
		CorrelationID: correlationID,
		OccurredAt:    time.Now().UTC(),
		Payload:       json.RawMessage(inner),
	}
	payload, err := json.Marshal(env)
	if err != nil {
		return err
	}
	_, err = tx.Exec(
		`INSERT INTO event_outbox(event_type, payload) VALUES(?, ?)`,
		eventType, payload,
	)
	return err
}

// HandleQueueStatus returns current queue depth by status.
func HandleQueueStatus(w http.ResponseWriter, r *http.Request, writeJSON func(http.ResponseWriter, *http.Request, int, interface{})) {
	var pending, processing, completed, failed, deadLetter, quarantined int
	dbpkg.DB.QueryRow(`SELECT COUNT(1) FROM write_jobs WHERE status='pending'`).Scan(&pending)
	dbpkg.DB.QueryRow(`SELECT COUNT(1) FROM write_jobs WHERE status='processing'`).Scan(&processing)
	dbpkg.DB.QueryRow(`SELECT COUNT(1) FROM write_jobs WHERE status='completed'`).Scan(&completed)
	dbpkg.DB.QueryRow(`SELECT COUNT(1) FROM write_jobs WHERE status='failed'`).Scan(&failed)
	dbpkg.DB.QueryRow(`SELECT COUNT(1) FROM write_jobs WHERE status='dead_letter'`).Scan(&deadLetter)
	dbpkg.DB.QueryRow(`SELECT COUNT(1) FROM write_jobs WHERE status='quarantined'`).Scan(&quarantined)
	var oldestSec float64
	dbpkg.DB.QueryRow(`SELECT COALESCE(CAST((julianday('now')-julianday(MIN(created_at)))*86400 AS INTEGER),0) FROM write_jobs WHERE status='pending'`).Scan(&oldestSec)
	writeJSON(w, r, 200, map[string]interface{}{
		"pending": pending, "processing": processing, "completed": completed,
		"failed": failed, "dead_letter": deadLetter, "quarantined": quarantined,
		"oldest_pending_seconds": oldestSec, "maintenance_mode": config.Cfg.MaintenanceMode,
	})
}

// HandleQueueReplay moves dead-letter jobs back to pending with safety controls (ADR-0035).
func HandleQueueReplay(w http.ResponseWriter, r *http.Request, writeJSON func(http.ResponseWriter, *http.Request, int, interface{}), writeAPIError func(http.ResponseWriter, *http.Request, int, string, string, string)) {
	rows, err := dbpkg.DB.Query(`SELECT id,replay_count FROM write_jobs WHERE status='dead_letter' LIMIT ?`, config.Cfg.ReplayBatchLimit+50)
	if err != nil {
		writeAPIError(w, r, 500, "db_error", "replay query failed: "+err.Error(), "/docs/api/queue")
		return
	}
	var quarantineIDs, replayIDs []int64
	for rows.Next() {
		var id int64
		var replayCount int
		rows.Scan(&id, &replayCount)
		if replayCount >= config.Cfg.MaxReplayCount {
			quarantineIDs = append(quarantineIDs, id)
		} else if len(replayIDs) < config.Cfg.ReplayBatchLimit {
			replayIDs = append(replayIDs, id)
		}
	}
	_ = rows.Err() // best-effort batch; the next replay sweep picks up any remainder
	rows.Close()
	for _, id := range quarantineIDs {
		_, _ = dbpkg.WDB.Exec(`UPDATE write_jobs SET status='quarantined' WHERE id=?`, id)
		atomic.AddInt64(&metrics.MetricPoisonJobsQuarantined, 1)
		logging.LogJSON(logging.LogFields{Level: "warn", Component: "queue-replay", Msg: fmt.Sprintf("job %d quarantined after %d replays (ADR-0035)", id, config.Cfg.MaxReplayCount)})
	}
	replayed := int64(0)
	for _, id := range replayIDs {
		result, err := dbpkg.WDB.Exec(`UPDATE write_jobs SET status='pending',retries=0,retry_at=NULL,replay_count=replay_count+1 WHERE id=? AND status='dead_letter'`, id)
		if err == nil {
			if n, _ := result.RowsAffected(); n > 0 {
				replayed++
			}
		}
	}
	logging.LogInfo("queue", fmt.Sprintf("replay: replayed=%d quarantined=%d batch_limit=%d", replayed, len(quarantineIDs), config.Cfg.ReplayBatchLimit))
	writeJSON(w, r, 200, map[string]interface{}{
		"status": "ok", "replayed": replayed,
		"skipped_quarantined": len(quarantineIDs),
		"batch_limit":         config.Cfg.ReplayBatchLimit,
		"max_replay_count":    config.Cfg.MaxReplayCount,
	})
}

// boolToInt maps a Go bool to the 0/1 integer SQLite stores for a boolean-typed
// column (e.g. articles.is_page), keeping the INSERT explicit rather than relying
// on driver bool coercion.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
