// SPDX-License-Identifier: Apache-2.0

// Package aiassist provides an opt-in, sovereign AI writing assistant for the
// VayuPress editor.
//
// Sovereignty first: the assistant talks to a LOCAL, operator-run inference
// server using the Ollama HTTP API (POST /api/generate). Nothing is sent to a
// hosted third-party model — the operator points VAYU_AI_URL at their own Ollama
// (or any Ollama-compatible) endpoint and chooses the model. When unconfigured,
// the assistant is disabled and the editor simply hides the feature.
//
// The assistant is deliberately stateless and prompt-driven: each operation is a
// small instruction wrapped around the author's text. It never auto-edits
// content — it returns suggestions the author chooses to apply (consistent with
// the project's "no autonomous actions" ethics charter).
package aiassist

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Operations supported by the assistant.
const (
	OpSummarize = "summarize"
	OpImprove   = "improve"
	OpTitles    = "titles"
	OpSEO       = "seo"
	OpContinue  = "continue"
	// OpDraft writes a complete post in Markdown from a free-form instruction —
	// the "give a prompt, get a draft" editor flow.
	OpDraft = "draft"
)

// Provider kinds for a runtime-selected backend.
const (
	KindOllama = "ollama" // native Ollama /api/generate protocol
	KindOpenAI = "openai" // OpenAI-compatible /chat/completions (OpenAI, OpenRouter, …)
)

// Backend selects the inference provider for a one-off generation. It lets the
// editor pick a provider at request time — a local Ollama, or any
// OpenAI-compatible endpoint (OpenAI, OpenRouter, or a custom gateway) whose
// base URL + API key the operator stored in VayuOS.
type Backend struct {
	Kind     string // KindOllama | KindOpenAI
	Endpoint string // base URL (Ollama root, or the OpenAI-compatible base ending in /v1)
	APIKey   string // bearer token for OpenAI-compatible providers (empty for Ollama)
	Model    string // model name

	// Temperature is the sampling temperature. Zero means "send nothing and let
	// the provider default apply" — a real 0 is expressed as a pointer-free
	// convention we deliberately avoid, because silently sending 0 would make
	// every draft deterministic for operators who never touched the setting.
	Temperature float64
	// MaxTokens caps the completion length. Zero sends no cap.
	MaxTokens int
	// ExcludeReasoning asks the provider not to return a separate reasoning stream,
	// so a reasoning model answers in "content" like any other. OpenRouter honours
	// this; it is only set for providers known to accept it, because a strict
	// OpenAI-compatible gateway rejects unknown request fields outright.
	ExcludeReasoning bool
	// Referer and Title are optional attribution headers. OpenRouter shows them
	// on the operator's own activity dashboard, which is how a self-hoster tells
	// their site's spend apart from everything else on the same key.
	Referer string
	Title   string
}

// ProviderError is a failure the PROVIDER itself reported about the request —
// no credits, unknown model, rate limited, an empty completion. It is separated
// from transport and decode errors on purpose: a transport error's text contains
// the configured endpoint URL (which may be an internal host), while a provider
// message is about the request and is safe to show the author who triggered it.
// Only this type should ever be surfaced in a UI.
//
// Message is scrubbed of anything URL-shaped before it is stored, so a custom
// gateway that echoes its own address back cannot leak it through this path.
type ProviderError struct {
	Status  int    // HTTP status, 0 when the failure was in a 2xx body
	Message string // the provider's own explanation, scrubbed
}

func (e *ProviderError) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("provider rejected the request (HTTP %d): %s", e.Status, e.Message)
	}
	return e.Message
}

// providerErr builds a ProviderError with the message scrubbed.
func providerErr(status int, format string, args ...interface{}) error {
	return &ProviderError{Status: status, Message: scrubURLs(fmt.Sprintf(format, args...))}
}

// scrubURLs removes URL-shaped and host-shaped text so a provider message can be
// shown without disclosing where the operator's gateway lives.
func scrubURLs(s string) string {
	out := urlPattern.ReplaceAllString(s, "[endpoint]")
	return strings.TrimSpace(hostPortPattern.ReplaceAllString(out, "[host]"))
}

var (
	urlPattern      = regexp.MustCompile(`(?i)\b(?:https?|ws|wss)://[^\s"'` + "`" + `]+`)
	hostPortPattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b|\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+:\d+\b`)
)

// Meta describes how a generation ended, for reporting back to the author.
type Meta struct {
	// Truncated is true when the model stopped because it hit the token cap
	// rather than because it finished. The draft is still usable, but it ends
	// mid-thought and the author needs to know that before publishing.
	Truncated bool
	// FromReasoning is true when the text came from a reasoning model's
	// "reasoning" field because "content" was empty.
	FromReasoning bool
	// Model is what the provider reports it actually served, which can differ
	// from what was asked for (OpenRouter reroutes ":free" variants).
	Model string
}

// Config configures the local inference endpoint.
type Config struct {
	URL   string // base URL of the Ollama server, e.g. http://localhost:11434
	Model string // model name, e.g. "llama3.2"
}

// Client calls a local Ollama-compatible inference server.
type Client struct {
	cfg     Config
	http    *http.Client
	enabled bool
}

// New builds a Client. A blank URL yields a disabled client.
func New(cfg Config, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	if cfg.Model == "" {
		cfg.Model = "llama3.2"
	}
	return &Client{cfg: cfg, http: httpClient, enabled: strings.TrimSpace(cfg.URL) != ""}
}

// Enabled reports whether a local model endpoint is configured.
func (c *Client) Enabled() bool { return c.enabled }

// Model returns the configured model name.
func (c *Client) Model() string { return c.cfg.Model }

// Endpoint returns the configured provider base URL.
//
// Exposed so a caller can tell a LOCAL provider from a remote one. That is not
// cosmetic: a remote provider makes a generation an outbound call, which a Tor
// Space forbids and which spends an egress budget, and no caller can answer
// that question without seeing where the provider lives.
func (c *Client) Endpoint() string { return c.cfg.URL }

// SupportedOps lists the operation identifiers the assistant accepts.
func SupportedOps() []string {
	return []string{OpSummarize, OpImprove, OpTitles, OpSEO, OpContinue, OpDraft}
}

// GenerateOpDetail runs op over text against an explicit, runtime-selected backend
// (Ollama, OpenAI, OpenRouter, or any OpenAI-compatible gateway). It is the
// stateless path the editor's provider picker uses; the env-configured Client
// above remains for the default local-Ollama assist. text is capped to bound the
// prompt. A nil httpClient gets a 90s default.
//
// It returns how the generation ended alongside the text, so a caller can tell the
// author that a draft was truncated or came from a reasoning field instead of
// silently handing over a partial post.
func GenerateOpDetail(ctx context.Context, hc *http.Client, b Backend, op, text string) (string, Meta, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", Meta{}, fmt.Errorf("text is required")
	}
	if len(text) > 12000 {
		text = text[:12000]
	}
	prompt, ok := buildPrompt(op, text)
	if !ok {
		return "", Meta{}, fmt.Errorf("unsupported operation %q", op)
	}
	if hc == nil {
		hc = &http.Client{Timeout: 90 * time.Second}
	}
	switch strings.ToLower(strings.TrimSpace(b.Kind)) {
	case KindOpenAI:
		return generateOpenAI(ctx, hc, b, prompt)
	default:
		out, err := generateOllamaAt(ctx, hc, b.Endpoint, b.Model, prompt)
		return out, Meta{Model: b.Model}, err
	}
}

// Assist runs op over text and returns the model's suggestion. text is capped to
// keep prompts bounded. Returns an error when disabled or on transport failure.
func (c *Client) Assist(ctx context.Context, op, text string) (string, error) {
	if !c.enabled {
		return "", fmt.Errorf("AI assistant is not configured (set VAYU_AI_URL)")
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return "", fmt.Errorf("text is required")
	}
	if len(text) > 12000 {
		text = text[:12000]
	}
	prompt, ok := buildPrompt(op, text)
	if !ok {
		return "", fmt.Errorf("unsupported operation %q", op)
	}
	return c.generate(ctx, prompt)
}

// generate calls the env-configured local Ollama for the default assist Client.
func (c *Client) generate(ctx context.Context, prompt string) (string, error) {
	return generateOllamaAt(ctx, c.http, c.cfg.URL, c.cfg.Model, prompt)
}

// generateOllamaAt calls an Ollama /api/generate endpoint with streaming off.
func generateOllamaAt(ctx context.Context, hc *http.Client, base, model, prompt string) (string, error) {
	if strings.TrimSpace(model) == "" {
		model = "llama3.2"
	}
	body, _ := json.Marshal(map[string]interface{}{
		"model":  model,
		"prompt": prompt,
		"stream": false,
	})
	endpoint := strings.TrimRight(base, "/") + "/api/generate"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("ai request: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		Response string `json:"response"`
		Error    string `json:"error"`
	}
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if out.Error != "" {
			return "", fmt.Errorf("provider rejected the request (HTTP %d): %s", resp.StatusCode, out.Error)
		}
		if snip := snippet(raw); snip != "" {
			return "", fmt.Errorf("provider rejected the request (HTTP %d): %s", resp.StatusCode, snip)
		}
		return "", fmt.Errorf("provider rejected the request (HTTP %d)", resp.StatusCode)
	}
	if out.Error != "" {
		return "", fmt.Errorf("the model reported an error: %s", out.Error)
	}
	// Empty must be an error here too, for the same reason as the OpenAI path.
	if strings.TrimSpace(out.Response) == "" {
		return "", fmt.Errorf("the model returned an empty draft")
	}
	return strings.TrimSpace(out.Response), nil
}

// generateOpenAI calls an OpenAI-compatible /chat/completions endpoint (OpenAI,
// OpenRouter, or any compatible gateway) with streaming disabled.
func generateOpenAI(ctx context.Context, hc *http.Client, b Backend, prompt string) (string, Meta, error) {
	if strings.TrimSpace(b.Model) == "" {
		return "", Meta{}, providerErr(0, "a model name is required for this provider")
	}
	payload := map[string]interface{}{
		"model":    b.Model,
		"messages": []map[string]string{{"role": "user", "content": prompt}},
		"stream":   false,
	}
	if b.Temperature > 0 {
		payload["temperature"] = b.Temperature
	}
	if b.MaxTokens > 0 {
		payload["max_tokens"] = b.MaxTokens
	}
	if b.ExcludeReasoning {
		payload["reasoning"] = map[string]interface{}{"exclude": true}
	}
	body, _ := json.Marshal(payload)
	endpoint := strings.TrimRight(strings.TrimSpace(b.Endpoint), "/")
	if endpoint == "" {
		return "", Meta{}, fmt.Errorf("this provider has no endpoint configured")
	}
	if !strings.HasSuffix(endpoint, "/chat/completions") {
		endpoint += "/chat/completions"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", Meta{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if k := strings.TrimSpace(b.APIKey); k != "" {
		req.Header.Set("Authorization", "Bearer "+k)
	}
	// Attribution headers, when the caller supplies them. Harmless to providers
	// that ignore them, and they are what make a shared OpenRouter key's activity
	// log legible per site.
	if v := strings.TrimSpace(b.Referer); v != "" {
		req.Header.Set("HTTP-Referer", v)
	}
	if v := strings.TrimSpace(b.Title); v != "" {
		req.Header.Set("X-Title", v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", Meta{}, fmt.Errorf("ai request: %w", err)
	}
	defer resp.Body.Close()

	// Read the body up front, whatever the status. A provider explains a refusal
	// in the body — "insufficient credits", "model not available to this key",
	// "rate limited" — and throwing that away leaves an operator with nothing to
	// act on but "it failed".
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		Model   string `json:"model"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content string `json:"content"`
				// Reasoning models answer here and leave Content empty.
				Reasoning string `json:"reasoning"`
			} `json:"message"`
		} `json:"choices"`
		Error struct {
			Message string `json:"message"`
			Code    any    `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &out) // best-effort: a non-JSON error body is handled below

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if msg := strings.TrimSpace(out.Error.Message); msg != "" {
			return "", Meta{}, providerErr(resp.StatusCode, "%s", msg)
		}
		// No parseable message: include a bounded snippet so the cause is still
		// diagnosable, rather than reporting only a bare status code.
		if snip := snippet(raw); snip != "" {
			return "", Meta{}, providerErr(resp.StatusCode, "%s", snip)
		}
		return "", Meta{}, providerErr(resp.StatusCode, "the provider gave no reason")
	}
	if readErr != nil {
		return "", Meta{}, fmt.Errorf("ai read: %w", readErr)
	}
	// A 2xx can still carry an error object instead of choices.
	if msg := strings.TrimSpace(out.Error.Message); msg != "" {
		return "", Meta{}, providerErr(0, "the model reported an error: %s", msg)
	}
	if len(out.Choices) == 0 {
		if snip := snippet(raw); snip != "" {
			return "", Meta{}, providerErr(0, "the provider returned no completion: %s", snip)
		}
		return "", Meta{}, providerErr(0, "the provider returned no completion")
	}

	meta := Meta{
		Truncated: strings.EqualFold(out.Choices[0].FinishReason, "length"),
		Model:     strings.TrimSpace(out.Model),
	}
	text := strings.TrimSpace(out.Choices[0].Message.Content)
	if text != "" {
		clean, err := sanitizeDraft(text)
		if err != nil {
			return "", meta, err
		}
		return clean, meta, nil
	}
	if text == "" {
		// Reasoning models put their answer in "reasoning". Sometimes that IS the
		// finished post; often it is the model talking to itself. Only a
		// recognisably shaped article is accepted, because inserting a stream of
		// thought as a 2,000-word draft is worse than reporting the failure — the
		// author has to read it all to discover it is not a post.
		if r := strings.TrimSpace(out.Choices[0].Message.Reasoning); r != "" {
			clean, err := sanitizeDraft(r)
			if err != nil {
				return "", meta, err
			}
			return clean, Meta{Truncated: meta.Truncated, Model: meta.Model, FromReasoning: true}, nil
		}
		// Genuinely empty. This MUST be an error: returning "" with a nil error is
		// indistinguishable from success, so the caller inserts nothing while the
		// server logs no failure — the exact shape of a silent dead feature.
		reason := "the model returned an empty draft"
		if meta.Truncated {
			reason += " (it hit the token limit before writing anything — raise the length cap)"
		} else if out.Choices[0].FinishReason != "" {
			reason += " (finish reason: " + out.Choices[0].FinishReason + ")"
		}
		return "", meta, providerErr(0, "%s", reason)
	}
	return text, meta, nil
}

// sanitizeDraft turns raw model output into a draft, or explains why it is not one.
//
// Salvage comes before judgement on purpose: a reply is usually either an article,
// or an article with a lead-in that can simply be cut. Only what survives both is
// refused, so the author loses a draft solely when there was never one there.
func sanitizeDraft(raw string) (string, error) {
	// Garbage first: leaked tokens and script salad disqualify a reply wherever they
	// appear, so there is nothing to salvage.
	if bad, why := unusableGarbage(raw); bad {
		return "", providerErr(0, "%s", why)
	}
	// Then salvage, and only judge what is left. Judging first rejected a perfectly
	// good article merely because the model cleared its throat before writing it.
	text := TrimToArticle(raw)
	if bad, why := Unusable(text); bad {
		return "", providerErr(0, "%s", why)
	}
	if !hasHeading(text) {
		// No heading anywhere. The prompt demands an <h1>, so this is prose about the
		// request or a wall of text, not the article. Refusing costs the occasional
		// heading-less draft; accepting costs the author the time to read a monologue
		// before discovering it is not a post.
		return "", providerErr(0, "%s",
			"the model replied without a single heading, so it never wrote the structured article that was asked for — "+
				"reasoning models often do this; try a model that returns a normal completion")
	}
	// The trim guarantees this for anything with a heading, so a failure here means
	// the heading sits somewhere a cut could not reach.
	if !StartsLikeArticle(text) {
		return "", providerErr(0, "%s",
			"the model wrapped its article in commentary that could not be separated cleanly — try again, or use a different model")
	}
	return text, nil
}

// snippet reduces an unexpected provider body to something safe and short enough
// to show an operator: one line, bounded, with no surrounding markup.
func snippet(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return ""
	}
	s = strings.Join(strings.Fields(s), " ")
	const max = 200
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

// buildPrompt returns the instruction prompt for op, or ok=false if unknown.
func buildPrompt(op, text string) (string, bool) {
	switch op {
	case OpSummarize:
		return "Summarize the following article in 2-3 concise sentences suitable " +
			"for a meta description. Return only the summary.\n\n" + text, true
	case OpImprove:
		return "Improve the clarity, grammar, and flow of the following text " +
			"without changing its meaning or adding new facts. Return only the " +
			"revised text.\n\n" + text, true
	case "rewrite":
		// The editor's slash palette sends op "rewrite" (admin-os-editor.js
		// AI_CMDS); before Wave 1 this fell through to unsupported and every
		// click failed. Rewrite IS improve-clarity — map it instead of failing.
		return buildPrompt(OpImprove, text)
	case OpTitles:
		return "Suggest 5 concise, compelling title options for the following " +
			"article. Return them as a numbered list, nothing else.\n\n" + text, true
	case OpSEO:
		return "Act as an SEO editor. For the following article, suggest: a meta " +
			"title (<=60 chars), a meta description (<=155 chars), and 5 focus " +
			"keywords. Return as a short labelled list.\n\n" + text, true
	case OpContinue:
		return "Continue writing the following article in the same voice and " +
			"style. Add one or two coherent paragraphs. Return only the new text.\n\n" + text, true
	case OpDraft:
		return draftPrompt(text), true
	default:
		return "", false
	}
}

// draftPrompt builds the instruction for a full post.
//
// It asks for semantic HTML rather than Markdown. HTML is what the editor
// ultimately stores, the importer parses it losslessly into blocks, and — the
// practical reason — a weak model producing malformed HTML degrades into
// recognisable soup that the quality gate catches, whereas malformed Markdown
// silently imports as one long paragraph that looks like a real draft.
//
// The structure requirements are not decoration. They are the two things that
// decide whether a post earns traffic:
//
//   - Classic SEO: one H1, a descriptive H2/H3 outline, short scannable
//     paragraphs, lists and tables where they carry meaning.
//   - Generative-engine optimisation: an answer engine quotes a passage only if
//     that passage stands alone. So the opening must answer the question in its
//     first two sentences, each section must be self-contained (no "as mentioned
//     above"), claims must be concrete, and an explicit FAQ gives the engine
//     question-shaped text to lift.
//
// Both are stated as hard requirements because a model asked merely to "write a
// good post" produces an essay: one long introduction, no headings a reader can
// scan, and nothing an engine can quote.
func draftPrompt(text string) string {
	return `You are writing a publication-ready article for a self-hosted blog.

Return ONLY semantic HTML — no Markdown, no code fences, no front-matter, no
commentary before or after, and no explanation of what you are doing. Do not
include <html>, <head> or <body>; return only the article's own elements.

Use exactly these elements: <h1> once, then <h2>/<h3>, <p>, <ul>/<ol> with <li>,
<blockquote>, <table> with <thead>/<tbody>/<tr>/<th>/<td>, <strong>, <em>, <a href>,
and <code>/<pre> for code.

Structure, in order:
1. One <h1> containing the main topic in natural language.
2. An opening <p> that answers the reader's question directly in its first two
   sentences. State the answer before any context or history.
3. A "Key takeaways" <h2> followed by a <ul> of 3-5 self-contained points, each a
   complete statement that makes sense quoted on its own.
4. The body, as several <h2> sections with <h3> subsections where a section has
   distinct parts. Every <h2> must be a specific, descriptive phrase — never
   "Introduction", "Overview" or "Conclusion".
5. A <h2>Frequently asked questions</h2> section with each question as its own
   <h3> and a direct answer in one or two <p> beneath it.

Requirements for every paragraph:
- Each section must stand alone. Never write "as mentioned above", "as we saw" or
  "in the previous section" — a search or answer engine may show that section by
  itself.
- Prefer concrete specifics — numbers, names, versions, steps, trade-offs — over
  adjectives. Do not claim facts you are unsure of; write what is verifiable.
- Short paragraphs, two to four sentences. No filler openings such as "In today's
  fast-paced world" or "It is important to note that".
- Use a <table> when comparing options and an <ol> when order matters.

Write the article now for this instruction:

` + text
}
