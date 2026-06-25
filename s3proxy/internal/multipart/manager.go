/*
Copyright (c) Intrinsec 2026

SPDX-License-Identifier: AGPL-3.0-only
*/

/*
Package multipart implements a disk-backed buffer for S3 multipart uploads.

s3proxy's crypto path (AES-256-GCM-SIV envelope) is two-pass and cannot stream,
so multipart uploads cannot be encrypted part-by-part. Instead the Manager
accepts the full multipart protocol, buffers each part to local disk, and on
completion concatenates the parts into a single plaintext buffer that the caller
encrypts and stores upstream as one PutObject.

Because the buffers are node-local and the in-memory session table is not
persisted, the Manager is a single-instance, session-affinity component: every
UploadPart for a given upload must reach the process that created it, and a
restart drops in-flight uploads (their on-disk directories are reclaimed by the
orphan sweep). See Cleanup.
*/
package multipart

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// maxPartNumber is the S3 ceiling on the part number in an UploadPart request.
const maxPartNumber = 10000

// cleanupInterval bounds how often the Cleanup goroutine evicts expired sessions
// and sweeps orphaned directories. It is clamped to the configured TTL so a short
// TTL still gets timely collection.
const cleanupInterval = 5 * time.Minute

var (
	// ErrUploadNotFound is returned when an uploadID has no live session (never
	// created, already completed/aborted, or lost to a restart).
	ErrUploadNotFound = errors.New("multipart upload not found")
	// ErrInvalidPart is returned for an out-of-range part number or a part that is
	// referenced at completion but was never uploaded.
	ErrInvalidPart = errors.New("invalid multipart part")
	// ErrObjectTooLarge is returned when a part write or the assembled object would
	// exceed the configured maximum object size.
	ErrObjectTooLarge = errors.New("multipart object exceeds maximum size")
)

// Metadata captures the request fields recorded at CreateMultipartUpload time and
// replayed at completion to build the single upstream PutObject.
type Metadata struct {
	ContentType               string
	Tags                      string
	UserMetadata              map[string]string
	ObjectLockLegalHoldStatus string
	ObjectLockMode            string
	ObjectLockRetainUntilDate time.Time
	SSECustomerAlgorithm      string
	SSECustomerKey            string
	SSECustomerKeyMD5         string
}

// Metrics is the subset of monitoring counters the Manager updates. It is
// satisfied by the process Metrics bundle (wired in a later phase) and may be nil,
// in which case all updates are no-ops.
type Metrics interface {
	AddUploadsActive(delta float64)
	IncParts()
	AddBufferBytes(delta float64)
	ObserveAssembleSeconds(seconds float64)
}

// partInfo records the on-disk size and synthesized ETag of a buffered part.
type partInfo struct {
	size int64
	etag string
}

// session holds the state of a single in-flight multipart upload. Its own mutex
// guards parts so concurrent UploadPart writes to different parts of the same
// upload do not race; the Manager mutex guards the sessions map.
type session struct {
	uploadID  string
	bucket    string
	key       string
	dir       string
	createdAt time.Time
	meta      Metadata

	mu    sync.Mutex
	parts map[int]partInfo
}

// Manager owns the on-disk buffer directory and the in-memory table of in-flight
// multipart uploads.
type Manager struct {
	baseDir       string
	maxObjectSize int64
	ttl           time.Duration
	log           *slog.Logger
	metrics       Metrics

	// now is the clock used for TTL eviction; overridable in tests.
	now func() time.Time

	mu       sync.Mutex
	sessions map[string]*session
}

// NewManager creates the buffer directory and returns a ready Manager. log must be
// non-nil; metrics may be nil.
func NewManager(baseDir string, maxObjectSize int64, ttl time.Duration, log *slog.Logger, metrics Metrics) (*Manager, error) {
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating multipart buffer dir %q: %w", baseDir, err)
	}
	return &Manager{
		baseDir:       baseDir,
		maxObjectSize: maxObjectSize,
		ttl:           ttl,
		log:           log,
		metrics:       metrics,
		now:           time.Now,
		sessions:      make(map[string]*session),
	}, nil
}

// Create registers a new upload, creates its on-disk directory and returns the
// generated uploadID.
func (m *Manager) Create(bucket, key string, meta Metadata) (string, error) {
	uploadID := uuid.NewString()
	dir := filepath.Join(m.baseDir, uploadID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating upload dir: %w", err)
	}

	s := &session{
		uploadID:  uploadID,
		bucket:    bucket,
		key:       key,
		dir:       dir,
		createdAt: m.now(),
		meta:      meta,
		parts:     make(map[int]partInfo),
	}

	m.mu.Lock()
	m.sessions[uploadID] = s
	m.mu.Unlock()

	m.addUploadsActive(1)
	m.log.Debug("multipart upload created", "upload_id", uploadID, "bucket", bucket, "key", key)
	return uploadID, nil
}

// WritePart streams body to part-<partNumber> (overwriting any previous upload of
// the same part), enforces the running object-size cap, and returns the part's
// hex MD5 ETag. The cap is checked against the sum of the other parts so a
// re-upload of an existing part is sized correctly.
func (m *Manager) WritePart(uploadID string, partNumber int, body io.Reader) (string, error) {
	if partNumber < 1 || partNumber > maxPartNumber {
		return "", fmt.Errorf("%w: part number %d out of range [1,%d]", ErrInvalidPart, partNumber, maxPartNumber)
	}

	s, err := m.lookup(uploadID)
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Budget for this part is the cap minus everything already buffered for the
	// other parts; a re-upload of partNumber does not count against itself.
	var others int64
	for n, p := range s.parts {
		if n != partNumber {
			others += p.size
		}
	}
	budget := m.maxObjectSize - others

	partPath := filepath.Join(s.dir, fmt.Sprintf("part-%d", partNumber))
	// #nosec G304 -- partPath is derived from the manager-owned baseDir, a UUID and a validated part number.
	f, err := os.OpenFile(partPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("opening part file: %w", err)
	}

	// #nosec G401 -- MD5 only synthesizes the S3 part ETag, not for security.
	h := md5.New()
	// Read one byte past the budget so we can detect an over-cap part without
	// trusting any client-provided length.
	written, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, budget+1))
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(partPath)
		return "", fmt.Errorf("writing part: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(partPath)
		return "", fmt.Errorf("closing part file: %w", closeErr)
	}
	if written > budget {
		_ = os.Remove(partPath)
		return "", fmt.Errorf("%w: part %d would push the object past %d bytes", ErrObjectTooLarge, partNumber, m.maxObjectSize)
	}

	etag := hex.EncodeToString(h.Sum(nil))

	prev, existed := s.parts[partNumber]
	s.parts[partNumber] = partInfo{size: written, etag: etag}

	delta := written
	if existed {
		delta -= prev.size
	} else {
		m.incParts()
	}
	m.addBufferBytes(delta)

	return etag, nil
}

// Assemble validates that every requested part exists, preallocates the total
// size, reads the parts in the given order into a single buffer, and returns it
// with the captured metadata. The order of parts is the caller's responsibility
// (it mirrors the client's CompleteMultipartUpload part list).
func (m *Manager) Assemble(uploadID string, parts []int) ([]byte, Metadata, error) {
	s, err := m.lookup(uploadID)
	if err != nil {
		return nil, Metadata{}, err
	}

	start := m.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	var total int64
	for _, n := range parts {
		p, ok := s.parts[n]
		if !ok {
			return nil, Metadata{}, fmt.Errorf("%w: part %d was not uploaded", ErrInvalidPart, n)
		}
		total += p.size
	}
	if total > m.maxObjectSize {
		return nil, Metadata{}, fmt.Errorf("%w: assembled size %d exceeds %d", ErrObjectTooLarge, total, m.maxObjectSize)
	}

	data := make([]byte, total)
	var off int64
	for _, n := range parts {
		size := s.parts[n].size
		partPath := filepath.Join(s.dir, fmt.Sprintf("part-%d", n))
		// #nosec G304 -- partPath is derived from the manager-owned baseDir, a UUID and a validated part number.
		f, err := os.Open(partPath)
		if err != nil {
			return nil, Metadata{}, fmt.Errorf("opening part %d: %w", n, err)
		}
		if _, err := io.ReadFull(f, data[off:off+size]); err != nil {
			_ = f.Close()
			return nil, Metadata{}, fmt.Errorf("reading part %d: %w", n, err)
		}
		if err := f.Close(); err != nil {
			return nil, Metadata{}, fmt.Errorf("closing part %d: %w", n, err)
		}
		off += size
	}

	m.observeAssemble(m.now().Sub(start))
	return data, s.meta, nil
}

// Abort drops the session and removes its on-disk directory. It is idempotent:
// aborting an unknown upload is a no-op so it can double as post-completion
// cleanup.
func (m *Manager) Abort(uploadID string) error {
	m.mu.Lock()
	s, ok := m.sessions[uploadID]
	if ok {
		delete(m.sessions, uploadID)
	}
	m.mu.Unlock()
	if !ok {
		return nil
	}
	return m.discard(s)
}

// discard removes a session's directory and reverses its metric contributions.
func (m *Manager) discard(s *session) error {
	s.mu.Lock()
	bytesHeld := sessionBytes(s)
	dir := s.dir
	s.mu.Unlock()

	err := os.RemoveAll(dir)
	m.addUploadsActive(-1)
	m.addBufferBytes(-bytesHeld)
	if err != nil {
		return fmt.Errorf("removing upload dir: %w", err)
	}
	return nil
}

// Cleanup runs until ctx is cancelled, periodically evicting expired sessions and
// sweeping orphaned directories. It performs one sweep immediately so directories
// left by a previous run are reclaimed at startup.
func (m *Manager) Cleanup(ctx context.Context) {
	m.sweepOrphans()

	interval := cleanupInterval
	if m.ttl > 0 && m.ttl < interval {
		interval = m.ttl
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.evictExpired(m.now())
			m.sweepOrphans()
		}
	}
}

// evictExpired removes sessions whose age exceeds the TTL relative to now.
func (m *Manager) evictExpired(now time.Time) {
	m.mu.Lock()
	var expired []*session
	for id, s := range m.sessions {
		if now.Sub(s.createdAt) > m.ttl {
			expired = append(expired, s)
			delete(m.sessions, id)
		}
	}
	m.mu.Unlock()

	for _, s := range expired {
		if err := m.discard(s); err != nil {
			m.log.Warn("evicting expired multipart upload", "upload_id", s.uploadID, "error", err)
			continue
		}
		m.log.Info("evicted expired multipart upload", "upload_id", s.uploadID)
	}
}

// sweepOrphans removes directories under baseDir that no live session references
// and that are older than the TTL. After a restart the session table is empty, so
// every leftover directory is an orphan; the age guard avoids racing a concurrent
// Create.
func (m *Manager) sweepOrphans() {
	entries, err := os.ReadDir(m.baseDir)
	if err != nil {
		m.log.Warn("reading multipart buffer dir", "dir", m.baseDir, "error", err)
		return
	}

	m.mu.Lock()
	known := make(map[string]struct{}, len(m.sessions))
	for id := range m.sessions {
		known[id] = struct{}{}
	}
	m.mu.Unlock()

	now := m.now()
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, ok := known[e.Name()]; ok {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) <= m.ttl {
			continue
		}
		path := filepath.Join(m.baseDir, e.Name())
		if err := os.RemoveAll(path); err != nil {
			m.log.Warn("removing orphan multipart dir", "dir", path, "error", err)
			continue
		}
		m.log.Info("removed orphan multipart dir", "dir", path)
	}
}

// lookup returns the session for uploadID or ErrUploadNotFound.
func (m *Manager) lookup(uploadID string) (*session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[uploadID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUploadNotFound, uploadID)
	}
	return s, nil
}

// sessionBytes sums the buffered bytes of a session. Caller holds s.mu.
func sessionBytes(s *session) int64 {
	var total int64
	for _, p := range s.parts {
		total += p.size
	}
	return total
}

func (m *Manager) addUploadsActive(delta float64) {
	if m.metrics != nil {
		m.metrics.AddUploadsActive(delta)
	}
}

func (m *Manager) incParts() {
	if m.metrics != nil {
		m.metrics.IncParts()
	}
}

func (m *Manager) addBufferBytes(delta int64) {
	if m.metrics != nil {
		m.metrics.AddBufferBytes(float64(delta))
	}
}

func (m *Manager) observeAssemble(d time.Duration) {
	if m.metrics != nil {
		m.metrics.ObserveAssembleSeconds(d.Seconds())
	}
}
