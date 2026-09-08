// SPDX-License-Identifier: Apache-2.0

// Package db manages the SQLite database, migrations, and WORM audit log.
package db

import (
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/johalputt/vayupress/internal/auth"
	"github.com/johalputt/vayupress/internal/config"
	"github.com/johalputt/vayupress/internal/logging"
	"github.com/johalputt/vayupress/internal/metrics"
	_ "github.com/mattn/go-sqlite3"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Article is the canonical domain model for a published piece of content.
type Article struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Slug      string    `json:"slug"`
	Content   string    `json:"content"`
	Tags      []string  `json:"tags"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// Status is "published" (publicly visible) or "draft" (visible only inside
	// VayuOS). Empty is treated as "published" for backward compatibility.
	Status string `json:"status,omitempty"`
	// AuthorID is the staff user this article is attributed to. Empty falls back
	// to the site-wide author at render time (multi-author, ADR).
	AuthorID string `json:"author_id,omitempty"`
	// DomainID is the VayuDomains owner of this article (migration 060). Empty
	// means the primary domain / unassigned — the historic default, so existing
	// content stays on the primary site. A secondary domain's id scopes the
	// article to that domain (ADR-0132, Stage 2).
	DomainID string `json:"domain_id,omitempty"`
	// IsPage marks a standalone page (is_page=1, migration 045) rather than a blog
	// post. It flows through the async create pipeline so a page is written with the
	// flag atomically, instead of being patched by a follow-up UPDATE that could
	// race the queued insert. Zero value (false) is a normal post — the historic
	// default — so existing create paths are unaffected.
	IsPage bool `json:"is_page,omitempty"`
}

// DB is the package-level database connection. It is the single, serialized
// writer (MaxOpenConns=1) — SQLite permits only one writer at a time, and
// pinning the writer to one connection keeps the WAL write path lock-free and
// SQLITE_BUSY-free.
var DB *sql.DB

// RDB is the read-only connection pool (audit F-4). SQLite in WAL mode allows
// one writer to run concurrently with many readers, so read traffic is fanned
// across several connections here instead of queuing behind the single writer.
// It is opened query_only as defense-in-depth: a stray write routed through the
// read path fails fast rather than silently contending with the writer. RDB is
// nil for in-memory databases (tests), where Reader() falls back to DB because
// each :memory: connection is a distinct database.
var RDB *sql.DB

// Reader returns the connection used for read-only queries: the dedicated read
// pool when available, otherwise the writer connection. Callers that only
// SELECT should prefer Reader() so reads do not serialize behind writes.
func Reader() *sql.DB {
	if RDB != nil {
		return RDB
	}
	return DB
}

// ClosePools closes the WAL read pools (RDB and ARDB). Called at the tail of
// graceful shutdown (main.go phase 7) to release the pool handles in a defined
// order after the primary DB closes; the pools live for the process lifetime
// otherwise. Also used by tests: on Windows an open pool handle keeps the
// database file locked, so a temp-dir cleanup cannot delete it and every
// otherwise-passing harness test reports a teardown failure.
func ClosePools() {
	if RDB != nil {
		_ = RDB.Close()
		RDB = nil
	}
	if ARDB != nil {
		_ = ARDB.Close()
		ARDB = nil
	}
}

// ARDB is the DEDICATED admin/VayuOS read pool — physically separate from the
// public read pool (RDB). This is the isolation guarantee that keeps VayuOS
// responsive "under any load": the public site, a bot/crawler flood, and a
// cold-cache render storm all contend on RDB, and no matter how saturated RDB
// gets, the admin console's own reads (the auth gate on every /os request, plus
// the analytics/monitoring dashboards) draw from ARDB and are never queued
// behind public traffic. A blocked public pool can no longer take the operator's
// control plane down with it. nil for in-memory DBs, where AdminReader() falls
// back to Reader()/DB.
var ARDB *sql.DB

// AdminReader returns the connection pool reserved for VayuOS/admin reads: the
// dedicated admin pool when available, otherwise the public read pool (or the
// writer for in-memory DBs). Admin-only read paths — the session/user auth gate
// and the operator dashboards — should use this so they are isolated from public
// read contention.
func AdminReader() *sql.DB {
	if ARDB != nil {
		return ARDB
	}
	return Reader()
}

// WDB is the wrapped DB that records write latency metrics.
var WDB wrappedDB

type wrappedDB struct{ *sql.DB }

// Exec wraps sql.DB.Exec, recording latency and slow-query metrics for writes.
func (w wrappedDB) Exec(query string, args ...interface{}) (sql.Result, error) {
	q := strings.ToUpper(strings.TrimSpace(query))
	isWrite := strings.HasPrefix(q, "INSERT") || strings.HasPrefix(q, "UPDATE") || strings.HasPrefix(q, "DELETE")
	if !isWrite {
		return w.DB.Exec(query, args...)
	}
	start := time.Now()
	result, err := w.DB.Exec(query, args...)
	elapsed := time.Since(start)
	metrics.SQLiteWriteLatency.Record(elapsed)
	if elapsed.Milliseconds() > 100 {
		atomic.AddInt64(&metrics.MetricSlowQueries, 1)
		logging.LogJSON(logging.LogFields{Level: "warn", Component: "db", Msg: fmt.Sprintf("slow write %dms: %s", elapsed.Milliseconds(), q[:minInt(len(q), 80)])})
	}
	return result, err
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Init opens the SQLite database, applies all PRAGMAs, runs migrations, and verifies checksums.
func Init() error {
	var err error
	dsn := config.Cfg.DBPath + "?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on&_synchronous=NORMAL"
	DB, err = sql.Open("sqlite3", dsn)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	DB.SetMaxOpenConns(1)
	DB.SetMaxIdleConns(1)
	DB.SetConnMaxLifetime(0)
	if err = DB.Ping(); err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	WDB = wrappedDB{DB}
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
		// Per-connection page cache. SQLite's cache is NOT shared between
		// connections, so the total heap it costs is (writer + readers) ×
		// cache_size. The read pool (openReadPool) sizes to NumCPU connections,
		// so a large per-connection cache multiplies fast on many-core hosts.
		// mmap_size below already keeps hot DB pages resident and shared via the
		// OS page cache, so a big private b-tree cache on top is largely
		// redundant. 32 MB on the single writer is ample headroom for the write +
		// admin path; readers use 16 MB (see openReadPool). This cut the steady
		// RSS by hundreds of MB on large stores with no measurable query-latency
		// change, because the working set stays served by mmap. (RAM audit 2026-07)
		"PRAGMA cache_size=-32768",   // 32 MB (writer)
		"PRAGMA mmap_size=536870912", // 512 MB — sized for 200k-post workloads; resident pages are OS-reclaimable
		"PRAGMA temp_store=MEMORY",
		"PRAGMA journal_size_limit=67108864",
		"PRAGMA wal_autocheckpoint=1000",
	}
	for _, p := range pragmas {
		if _, err := DB.Exec(p); err != nil {
			return fmt.Errorf("pragma %q: %w", p, err)
		}
	}
	if err := runMigrations(); err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	if err := verifyMigrationChecksums(); err != nil {
		return fmt.Errorf("migration drift: %w", err)
	}
	if err := openReadPool(); err != nil {
		return fmt.Errorf("read pool: %w", err)
	}
	if err := openAdminReadPool(); err != nil {
		return fmt.Errorf("admin read pool: %w", err)
	}
	logging.LogInfo("db", "ready — WAL+PRAGMAs enforced, migrations+checksums verified (ADR-0033/0034)")
	return nil
}

// isMemoryDB reports whether path refers to a SQLite in-memory database. Each
// connection to such a database is distinct, so a separate read pool cannot be
// opened against it.
func isMemoryDB(path string) bool {
	return path == ":memory:" ||
		strings.HasPrefix(path, "file::memory:") ||
		strings.Contains(path, "mode=memory")
}

const (
	// readPoolConnMaxLifetime retires each read-pool connection after this long
	// so no reader can hold a WAL read-mark indefinitely. This is what lets the
	// background checkpoint periodically find a reader-free moment and fully
	// reset/truncate the -wal file (see openReadPool for the full rationale).
	readPoolConnMaxLifetime = 3 * time.Minute
	// readPoolConnMaxIdleTime closes idle read-pool connections sooner, so quiet
	// periods leave no lingering reader pinning the WAL snapshot.
	readPoolConnMaxIdleTime = 45 * time.Second
	// walCheckpointInterval is how often the background TRUNCATE checkpoint runs.
	// It is deliberately tighter than the old 5-minute cadence: TRUNCATE is cheap
	// when the WAL is already small, and a shorter interval keeps the WAL bounded
	// between checkpoints even under heavy write bursts.
	walCheckpointInterval = 60 * time.Second
)

// readPoolSize returns how many connections the WAL read pool opens.
//
// SQLite in WAL mode allows many concurrent readers, and the bottleneck under
// load is read CONCURRENCY, not CPU. With only NumCPU connections a burst of
// uncached requests — a bot/crawler flood, or a cold cache right after a
// restart — drains the pool, and then EVERY uncached read queues behind it,
// including the VayuOS admin auth gate, which times out and returns 502 while
// the cache-served public site stays fast. Defaulting well above NumCPU keeps
// the admin panel reachable under public read floods. Tunable via
// VAYU_READ_POOL_SIZE (clamped 4..256). Each connection costs at most ~8 MB of
// page cache (see the DSN _cache_size), and that is allocated lazily, so the
// realistic memory cost is far below the worst case.
func readPoolSize() int {
	if v := strings.TrimSpace(os.Getenv("VAYU_READ_POOL_SIZE")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 4 && n <= 256 {
			return n
		}
	}
	n := runtime.NumCPU() * 4
	if n < 24 {
		n = 24
	}
	if n > 64 {
		n = 64
	}
	return n
}

// adminPoolSize returns how many connections the dedicated admin read pool
// (ARDB) opens. It is small on purpose: the admin console has at most a handful
// of concurrent operators, and a dashboard panel fires its ~dozen aggregate
// queries sequentially, so a modest, RESERVED pool keeps VayuOS instant without
// wasting memory. Its whole value is being separate from the public pool, not
// large. Tunable via VAYU_ADMIN_POOL_SIZE (clamped 2..64).
func adminPoolSize() int {
	if v := strings.TrimSpace(os.Getenv("VAYU_ADMIN_POOL_SIZE")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 2 && n <= 64 {
			return n
		}
	}
	n := runtime.NumCPU()
	if n < 8 {
		n = 8
	}
	if n > 16 {
		n = 16
	}
	return n
}

// openReadPool opens the read-only connection pool (RDB) against the same
// on-disk database file as the writer. It is a no-op for in-memory databases,
// where Reader() transparently falls back to the writer connection.
func openReadPool() error {
	if isMemoryDB(config.Cfg.DBPath) {
		return nil
	}
	// query_only + the read-relevant PRAGMAs applied per connection by the
	// driver. No mmap_size here: it is a writer-side optimisation and not a
	// recognised DSN parameter.
	//
	// _cache_size is deliberately modest (16 MB) because this pool opens NumCPU
	// connections and SQLite page cache is per-connection: at 64 MB × NumCPU the
	// read pool alone cost 256–512 MB of heap. mmap_size on the writer keeps hot
	// pages resident in the shared OS page cache, so 16 MB of private b-tree
	// cache per reader is enough for typical query working sets with no
	// measurable latency change. (RAM audit 2026-07)
	// Per-connection page cache reduced to 8 MB (from 16 MB): the pool now opens
	// many more connections (see readPoolSize) and SQLite's cache is
	// per-connection, so a smaller private cache keeps total heap in check while
	// mmap_size on the writer keeps hot pages resident in the shared OS page
	// cache. Point-lookup readers rarely fill even 8 MB.
	rdsn := config.Cfg.DBPath + "?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on&_synchronous=NORMAL&_query_only=true&_cache_size=-8192"
	rdb, err := sql.Open("sqlite3", rdsn)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	n := readPoolSize()
	rdb.SetMaxOpenConns(n)
	rdb.SetMaxIdleConns(n)
	// CRITICAL — WAL reclamation. Read-pool connections MUST be recycled, never
	// held open forever. In WAL mode a checkpoint can only reset/truncate the
	// -wal file when NO connection is holding an older read snapshot. With a pool
	// of never-recycled readers (the previous SetConnMaxLifetime(0)) under
	// continuous traffic there is almost always a live reader, so the checkpoint
	// can never reset the WAL: it grows without bound until reads crawl and the
	// dynamic VayuOS admin exceeds its timeout (502) — while the cache-served
	// public site, which touches no DB, stays fast. That is the true root cause
	// of the recurring post-restart/after-hours VayuOS 502s (every prior release
	// only moved more reads onto this pool, worsening the starvation). Retiring
	// connections on a bounded lifetime/idle window guarantees recurring moments
	// with no live reader, letting the checkpointer (now TRUNCATE — see
	// StartWALCheckpointGoroutine) fully reclaim the WAL. Empirically this bounds
	// a WAL that otherwise reached multi-GB under sustained load to a few dozen MB.
	rdb.SetConnMaxLifetime(readPoolConnMaxLifetime)
	rdb.SetConnMaxIdleTime(readPoolConnMaxIdleTime)
	if err := rdb.Ping(); err != nil {
		_ = rdb.Close()
		return fmt.Errorf("ping: %w", err)
	}
	RDB = rdb
	logging.LogInfo("db", fmt.Sprintf("read pool ready — %d WAL reader connections (query_only) [F-4]", n))
	return nil
}

// openAdminReadPool opens the DEDICATED admin/VayuOS read pool (ARDB) against the
// same on-disk database file. It is identical in kind to the public read pool
// (query_only, recycled connections, WAL) but physically separate and reserved
// for the admin console, so operator reads never queue behind a public read
// flood. No-op for in-memory databases (AdminReader falls back to Reader/DB).
func openAdminReadPool() error {
	if isMemoryDB(config.Cfg.DBPath) {
		return nil
	}
	rdsn := config.Cfg.DBPath + "?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on&_synchronous=NORMAL&_query_only=true&_cache_size=-8192"
	ardb, err := sql.Open("sqlite3", rdsn)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	n := adminPoolSize()
	ardb.SetMaxOpenConns(n)
	ardb.SetMaxIdleConns(n)
	// Same recycling discipline as the public pool so admin readers never pin the
	// WAL snapshot and block checkpointing (see openReadPool for the rationale).
	ardb.SetConnMaxLifetime(readPoolConnMaxLifetime)
	ardb.SetConnMaxIdleTime(readPoolConnMaxIdleTime)
	if err := ardb.Ping(); err != nil {
		_ = ardb.Close()
		return fmt.Errorf("ping: %w", err)
	}
	ARDB = ardb
	logging.LogInfo("db", fmt.Sprintf("admin read pool ready — %d reserved WAL reader connections (query_only)", n))
	return nil
}

// StartWALCheckpointGoroutine runs adaptive WAL checkpoints in the background (ADR-0033).
//
// Strategy: use PASSIVE by default — it never blocks readers or the writer,
// just checkpoints whatever frames it can. Combined with read-pool connection
// recycling (ConnMaxLifetime/ConnMaxIdleTime), PASSIVE is enough to keep the
// WAL bounded: recycled connections release their read snapshots, allowing the
// next PASSIVE run to checkpoint past them. Only when the WAL exceeds the
// configured threshold (indicating recycling alone isn't keeping up, e.g. under
// a sustained write flood) do we escalate to TRUNCATE, which requires an
// exclusive lock and MAY briefly stall readers — but only in this emergency
// path, not every tick. This avoids the 502 that a blanket TRUNCATE caused
// under continuous traffic (it blocked the writer for busy_timeout seconds
// waiting for readers to release).
func StartWALCheckpointGoroutine(doneCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(walCheckpointInterval)
		defer ticker.Stop()
		for {
			select {
			case <-doneCh:
				return
			case <-ticker.C:
				walMB := walFileSizeMB()
				// ALWAYS PASSIVE. PASSIVE never takes an exclusive lock, so it
				// never blocks a reader or the writer. Under a write-heavy load
				// (e.g. the analytics-beacon stream on every page view) the WAL
				// naturally sits near journal_size_limit (64 MB) — that is bounded
				// and completely fine. The previous TRUNCATE/RESTART escalation
				// tried to force the WAL smaller, but those modes need an exclusive
				// lock and, under continuous read traffic, stall EVERY reader for
				// up to busy_timeout (5s) each tick — which starved the dynamic
				// VayuOS admin into 502s. Connection recycling (openReadPool)
				// already provides reader-free windows in which even a PASSIVE
				// checkpoint resets the WAL back down to journal_size_limit, so we
				// never need the blocking modes on a timer.
				start := time.Now()
				var pagesWritten int
				err := DB.QueryRow(`PRAGMA wal_checkpoint(PASSIVE)`).Scan(new(int), new(int), &pagesWritten)
				if err != nil {
					logging.LogError("wal", "checkpoint error", err.Error())
				} else {
					elapsed := time.Since(start)
					atomic.AddInt64(&metrics.MetricWALCheckpoints, 1)
					atomic.AddInt64(&metrics.MetricWALCheckpointDurationMS, elapsed.Milliseconds())
					if walMB > float64(config.Cfg.WALSizeThresholdMB) {
						atomic.AddInt64(&metrics.MetricWALAdaptiveCheckpoints, 1)
					}
					logging.LogInfo("wal", fmt.Sprintf("checkpoint(PASSIVE) pages=%d dur=%dms wal=%.1fMB total=%d",
						pagesWritten, elapsed.Milliseconds(), walMB, atomic.LoadInt64(&metrics.MetricWALCheckpoints)))
				}
			}
		}
	}()
}

func walFileSizeMB() float64 {
	fi, err := os.Stat(config.Cfg.DBPath + "-wal")
	if err != nil {
		return 0
	}
	return float64(fi.Size()) / (1024 * 1024)
}

// StartStuckJobReaper resets stuck processing jobs every minute.
func StartStuckJobReaper(doneCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-doneCh:
				return
			case <-ticker.C:
				result, err := DB.Exec(`UPDATE write_jobs SET status='pending' WHERE status='processing' AND created_at < datetime('now','-5 minutes')`)
				if err != nil {
					logging.LogError("queue-reaper", "stuck job error", err.Error())
					continue
				}
				rows, _ := result.RowsAffected()
				if rows > 0 {
					atomic.AddInt64(&metrics.MetricQueueStuckResets, rows)
					logging.LogJSON(logging.LogFields{Level: "warn", Component: "queue-reaper", Msg: fmt.Sprintf("reset %d stuck jobs", rows)})
				}
			}
		}
	}()
}

// StartJobRetentionSweeper periodically prunes terminal write_jobs rows so the
// queue table — and therefore the database file — cannot grow without bound.
// Completed jobs are deleted after config.Cfg.JobRetentionHours; dead-letter and
// quarantined jobs after config.Cfg.DeadJobRetentionDays. Deletes run in bounded
// batches so each statement is short and never monopolises the single writer
// connection (the root cause of the periodic stalls fixed alongside this).
func StartJobRetentionSweeper(doneCh <-chan struct{}) {
	go func() {
		first := time.NewTimer(2 * time.Minute) // prune soon after start
		defer first.Stop()
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-doneCh:
				return
			case <-first.C:
				runJobRetention()
			case <-ticker.C:
				runJobRetention()
			}
		}
	}()
}

func runJobRetention() {
	n, err := PruneWriteJobsOnce()
	if err != nil {
		logging.LogError("queue-retention", "prune failed", err.Error())
		return
	}
	if n > 0 {
		logging.LogInfo("queue-retention", fmt.Sprintf("pruned %d terminal write_jobs", n))
	}
}

// PruneWriteJobsOnce deletes completed jobs older than the configured retention
// and dead-letter/quarantined jobs older than the dead-job retention, in bounded
// batches. It returns the total number of rows removed. Pending and processing
// jobs are never touched.
func PruneWriteJobsOnce() (int64, error) {
	if DB == nil {
		return 0, nil
	}
	hours := config.Cfg.JobRetentionHours
	if hours <= 0 {
		hours = 24
	}
	days := config.Cfg.DeadJobRetentionDays
	if days <= 0 {
		days = 7
	}
	var total int64
	n, err := pruneJobsBatched(
		`DELETE FROM write_jobs WHERE id IN (SELECT id FROM write_jobs WHERE status='completed' AND created_at < datetime('now', ?) LIMIT ?)`,
		fmt.Sprintf("-%d hours", hours))
	total += n
	if err != nil {
		return total, err
	}
	n, err = pruneJobsBatched(
		`DELETE FROM write_jobs WHERE id IN (SELECT id FROM write_jobs WHERE status IN ('dead_letter','quarantined') AND created_at < datetime('now', ?) LIMIT ?)`,
		fmt.Sprintf("-%d days", days))
	total += n
	return total, err
}

// pruneJobsBatched runs query in batches of 5000 (query takes the cutoff and the
// batch limit as bound parameters), pausing briefly between batches so other
// writes can interleave on the single writer connection.
func pruneJobsBatched(query, cutoff string) (int64, error) {
	const batch = 5000
	var total int64
	for {
		res, err := DB.Exec(query, cutoff, batch)
		if err != nil {
			return total, fmt.Errorf("prune write_jobs: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
		if n < batch {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	return total, nil
}

// InitStorageCachedBytes computes initial storage usage in the background.
func InitStorageCachedBytes() {
	go func() {
		start := time.Now()
		cacheSize, _ := StorageDirSizeBytes(config.Cfg.CacheDir)
		dbSize := int64(0)
		if fi, err := os.Stat(config.Cfg.DBPath); err == nil {
			dbSize = fi.Size()
		}
		total := cacheSize + dbSize
		atomic.StoreInt64(&metrics.CachedStorageBytes, total)
		logging.LogInfo("storage", fmt.Sprintf("initial scan: %s (%dms)", FormatBytes(total), time.Since(start).Milliseconds()))
	}()
}

// StorageUsedBytes returns the cached storage usage in bytes.
func StorageUsedBytes() int64 { return atomic.LoadInt64(&metrics.CachedStorageBytes) }

// UpdateStorageDelta adjusts the cached storage counter by delta bytes.
func UpdateStorageDelta(delta int64) { atomic.AddInt64(&metrics.CachedStorageBytes, delta) }

// StorageDirSizeBytes recursively sums the size of all files under root.
func StorageDirSizeBytes(root string) (int64, error) {
	var total int64
	err := walkDir(root, func(size int64) { total += size })
	return total, err
}

func walkDir(root string, fn func(int64)) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		path := root + "/" + e.Name()
		if e.IsDir() {
			_ = walkDir(path, fn)
			continue
		}
		if fi, err := e.Info(); err == nil {
			fn(fi.Size())
		}
	}
	return nil
}

// StorageQuotaBytes returns the configured storage quota in bytes.
func StorageQuotaBytes() int64 { return config.Cfg.StorageQuotaGB * 1024 * 1024 * 1024 }

// FormatBytes formats a byte count as a human-readable string.
func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// AuditLog appends a tamper-evident record to the WORM audit_log table.
func AuditLog(action, actor, target, detail string) {
	if DB == nil {
		return
	}
	if _, err := DB.Exec(
		`INSERT INTO audit_log(ts,action,actor,target,detail) VALUES(?,?,?,?,?)`,
		time.Now().UTC(), action, actor, target, detail,
	); err != nil {
		logging.LogJSON(logging.LogFields{Level: "error", Component: "audit", Msg: "failed to write audit record", Error: err.Error()})
	}
}

// AuditActor derives a stable actor identifier (client IP) from the request.
//
// It delegates to auth.ClientIP, which honours forwarding headers ONLY when the
// immediate peer is a configured trusted proxy. The previous implementation read
// X-Real-IP, then the FIRST X-Forwarded-For entry, with no peer check at all —
// so anyone able to reach the origin directly could write whatever actor they
// liked into the audit log, and the left-most XFF entry is the one a client
// prepends. An audit trail an attacker can author is worse than none: it does not
// merely fail to record them, it records someone else.
func AuditActor(r *http.Request) string {
	return auth.ClientIP(r)
}

// ── Migration system ──────────────────────────────────────────────────────────

type migration struct {
	Version  string
	Up       string
	Down     string
	Checksum string
}

func checksumSQL(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

var migrations []migration

func init() {
	var err error
	migrations, err = loadMigrationsFS(migrationFS)
	if err != nil {
		panic("db: failed to load embedded migrations: " + err.Error())
	}
}

// loadMigrationsFS reads *.up.sql files from fs, pairs each with an optional
// *.down.sql, computes the checksum of the up SQL, and returns a sorted slice.
func loadMigrationsFS(fs embed.FS) ([]migration, error) {
	entries, err := fs.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations dir: %w", err)
	}

	upFiles := make(map[string]string) // version → up SQL
	downFiles := make(map[string]string)

	for _, e := range entries {
		name := e.Name()
		b, err := fs.ReadFile("migrations/" + name)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		sql := strings.TrimRight(string(b), "\n")

		switch {
		case strings.HasSuffix(name, ".up.sql"):
			version := strings.TrimSuffix(name, ".up.sql")
			upFiles[version] = sql
		case strings.HasSuffix(name, ".down.sql"):
			version := strings.TrimSuffix(name, ".down.sql")
			downFiles[version] = sql
		}
	}

	versions := make([]string, 0, len(upFiles))
	for v := range upFiles {
		versions = append(versions, v)
	}
	sort.Strings(versions)

	result := make([]migration, 0, len(versions))
	for _, v := range versions {
		up := upFiles[v]
		result = append(result, migration{
			Version:  v,
			Up:       up,
			Down:     downFiles[v],
			Checksum: checksumSQL(up),
		})
	}
	return result, nil
}

// Migrations returns the full list of known migrations (used by health handlers).
func Migrations() []struct{ Version, Checksum string } {
	out := make([]struct{ Version, Checksum string }, len(migrations))
	for i, m := range migrations {
		out[i] = struct{ Version, Checksum string }{m.Version, m.Checksum}
	}
	return out
}

func runMigrations() error {
	dryRun := os.Getenv("VAYU_MIGRATE_DRY_RUN") == "true"
	if dryRun {
		logging.LogInfo("migrations", "DRY-RUN mode")
	}
	if !dryRun {
		if _, err := DB.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations(id INTEGER PRIMARY KEY AUTOINCREMENT,version TEXT UNIQUE NOT NULL,checksum TEXT NOT NULL DEFAULT '',applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`); err != nil {
			return fmt.Errorf("bootstrap schema_migrations: %w", err)
		}
	}
	for _, m := range migrations {
		if dryRun {
			logging.LogInfo("migrations", fmt.Sprintf("[dry-run] would apply: %s", m.Version))
			continue
		}
		var count int
		DB.QueryRow(`SELECT COUNT(1) FROM schema_migrations WHERE version=?`, m.Version).Scan(&count)
		if count > 0 {
			logging.LogInfo("migrations", "already applied: "+m.Version)
			continue
		}
		logging.LogInfo("migrations", "applying: "+m.Version)
		tx, err := DB.Begin()
		if err != nil {
			return fmt.Errorf("migration %s begin: %w", m.Version, err)
		}
		for _, stmt := range strings.Split(m.Up, "\n") {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			if _, err := tx.Exec(stmt); err != nil {
				tx.Rollback()
				if strings.Contains(err.Error(), "duplicate column") || strings.Contains(err.Error(), "already exists") {
					logging.LogInfo("migrations", "column exists in "+m.Version+" — continuing")
					tx2, _ := DB.Begin()
					if tx2 != nil {
						tx = tx2
					}
					continue
				}
				return fmt.Errorf("migration %s exec: %w", m.Version, err)
			}
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version,checksum) VALUES(?,?)`, m.Version, m.Checksum); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s record: %w", m.Version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migration %s commit: %w", m.Version, err)
		}
		logging.LogInfo("migrations", "applied: "+m.Version)
	}
	return nil
}

func verifyMigrationChecksums() error {
	rows, err := DB.Query(`SELECT version, checksum FROM schema_migrations ORDER BY id ASC`)
	if err != nil {
		return fmt.Errorf("verifyMigrationChecksums query: %w", err)
	}
	defer rows.Close()
	migMap := make(map[string]string)
	for _, m := range migrations {
		migMap[m.Version] = m.Checksum
	}
	var drifted []string
	for rows.Next() {
		var version, storedChecksum string
		rows.Scan(&version, &storedChecksum)
		if storedChecksum == "" {
			continue
		}
		expected, ok := migMap[version]
		if !ok {
			continue
		}
		if storedChecksum != expected {
			atomic.AddInt64(&metrics.MetricMigrationDriftDetected, 1)
			logging.LogJSON(logging.LogFields{Level: "error", Component: "migrations", Msg: fmt.Sprintf("CHECKSUM DRIFT: %s stored=%s expected=%s", version, storedChecksum[:8], expected[:8])})
			drifted = append(drifted, version)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("verifyMigrationChecksums iterate: %w", err)
	}
	if len(drifted) > 0 {
		return fmt.Errorf("migration drift detected: %s — startup halted (ADR-0034)", strings.Join(drifted, ", "))
	}
	logging.LogInfo("migrations", fmt.Sprintf("checksum verification passed: %d migrations (ADR-0034)", len(migMap)))
	return nil
}

// RollbackMigration rolls back the named migration.
func RollbackMigration(version string) error {
	for i := len(migrations) - 1; i >= 0; i-- {
		if migrations[i].Version != version {
			continue
		}
		if migrations[i].Down == "" {
			return fmt.Errorf("migration %s has no Down SQL", version)
		}
		tx, err := DB.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i].Down); err != nil {
			tx.Rollback()
			return fmt.Errorf("rollback exec %s: %w", version, err)
		}
		if _, err := tx.Exec(`DELETE FROM schema_migrations WHERE version=?`, version); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		logging.LogInfo("migrations", "rolled back: "+version)
		return nil
	}
	return fmt.Errorf("migration %s not found", version)
}
