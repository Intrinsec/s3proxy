/*
Copyright (c) Intrinsec 2026

SPDX-License-Identifier: AGPL-3.0-only
*/

package multipart

import (
	"bytes"
	"crypto/md5" //nolint:gosec // test asserts the manager's ETag matches the MD5 of the part.
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const testCap = 1 << 20 // 1 MiB

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(t.TempDir(), testCap, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func md5Hex(b []byte) string {
	sum := md5.Sum(b) //nolint:gosec // see import note.
	return hex.EncodeToString(sum[:])
}

func TestCreateRegistersSessionAndDir(t *testing.T) {
	m := newTestManager(t)

	id, err := m.Create("bucket", "key", Metadata{ContentType: "text/plain"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if id == "" {
		t.Fatal("Create returned empty uploadID")
	}

	if _, err := os.Stat(filepath.Join(m.baseDir, id)); err != nil {
		t.Fatalf("upload dir missing: %v", err)
	}
	if _, err := m.lookup(id); err != nil {
		t.Fatalf("session not registered: %v", err)
	}
}

func TestWritePartETagAndAssemble(t *testing.T) {
	m := newTestManager(t)
	id, err := m.Create("bucket", "key", Metadata{ContentType: "application/octet-stream"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	part1 := bytes.Repeat([]byte("a"), 1000)
	part2 := bytes.Repeat([]byte("b"), 500)

	// Upload out of order: part 2 first, then part 1.
	etag2, err := m.WritePart(id, 2, bytes.NewReader(part2))
	if err != nil {
		t.Fatalf("WritePart 2: %v", err)
	}
	if etag2 != md5Hex(part2) {
		t.Fatalf("etag2 = %s, want %s", etag2, md5Hex(part2))
	}
	etag1, err := m.WritePart(id, 1, bytes.NewReader(part1))
	if err != nil {
		t.Fatalf("WritePart 1: %v", err)
	}
	if etag1 != md5Hex(part1) {
		t.Fatalf("etag1 = %s, want %s", etag1, md5Hex(part1))
	}

	data, meta, err := m.Assemble(id, []int{1, 2})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	want := append(append([]byte{}, part1...), part2...)
	if !bytes.Equal(data, want) {
		t.Fatalf("assembled data mismatch: got %d bytes, want %d", len(data), len(want))
	}
	if meta.ContentType != "application/octet-stream" {
		t.Fatalf("metadata not preserved: %+v", meta)
	}
}

func TestWritePartReupload(t *testing.T) {
	m := newTestManager(t)
	id, _ := m.Create("bucket", "key", Metadata{})

	if _, err := m.WritePart(id, 1, bytes.NewReader(bytes.Repeat([]byte("x"), 100))); err != nil {
		t.Fatalf("first WritePart: %v", err)
	}
	newBody := bytes.Repeat([]byte("y"), 250)
	etag, err := m.WritePart(id, 1, bytes.NewReader(newBody))
	if err != nil {
		t.Fatalf("re-upload WritePart: %v", err)
	}
	if etag != md5Hex(newBody) {
		t.Fatalf("re-upload etag mismatch")
	}

	data, _, err := m.Assemble(id, []int{1})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if !bytes.Equal(data, newBody) {
		t.Fatalf("re-upload did not overwrite: got %d bytes", len(data))
	}
}

func TestWritePartCapEnforced(t *testing.T) {
	m, err := NewManager(t.TempDir(), 1000, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	id, _ := m.Create("bucket", "key", Metadata{})

	if _, err := m.WritePart(id, 1, bytes.NewReader(bytes.Repeat([]byte("a"), 600))); err != nil {
		t.Fatalf("WritePart 1: %v", err)
	}
	// Second part pushes total to 1100 > 1000.
	_, err = m.WritePart(id, 2, bytes.NewReader(bytes.Repeat([]byte("b"), 500)))
	if !errors.Is(err, ErrObjectTooLarge) {
		t.Fatalf("want ErrObjectTooLarge, got %v", err)
	}
	// The rejected part must not be left on disk.
	if _, statErr := os.Stat(filepath.Join(m.baseDir, id, "part-2")); !os.IsNotExist(statErr) {
		t.Fatalf("rejected part file still present: %v", statErr)
	}
}

func TestWritePartInvalidNumber(t *testing.T) {
	m := newTestManager(t)
	id, _ := m.Create("bucket", "key", Metadata{})

	for _, n := range []int{0, -1, maxPartNumber + 1} {
		if _, err := m.WritePart(id, n, bytes.NewReader([]byte("x"))); !errors.Is(err, ErrInvalidPart) {
			t.Fatalf("part %d: want ErrInvalidPart, got %v", n, err)
		}
	}
}

func TestWritePartUnknownUpload(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.WritePart("nope", 1, bytes.NewReader([]byte("x"))); !errors.Is(err, ErrUploadNotFound) {
		t.Fatalf("want ErrUploadNotFound, got %v", err)
	}
}

func TestAssembleMissingPart(t *testing.T) {
	m := newTestManager(t)
	id, _ := m.Create("bucket", "key", Metadata{})
	if _, err := m.WritePart(id, 1, bytes.NewReader([]byte("x"))); err != nil {
		t.Fatalf("WritePart: %v", err)
	}
	if _, _, err := m.Assemble(id, []int{1, 2}); !errors.Is(err, ErrInvalidPart) {
		t.Fatalf("want ErrInvalidPart, got %v", err)
	}
}

func TestAbortRemovesSessionAndDir(t *testing.T) {
	m := newTestManager(t)
	id, _ := m.Create("bucket", "key", Metadata{})
	if _, err := m.WritePart(id, 1, bytes.NewReader([]byte("data"))); err != nil {
		t.Fatalf("WritePart: %v", err)
	}
	dir := filepath.Join(m.baseDir, id)

	if err := m.Abort(id); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("dir not removed: %v", err)
	}
	if _, err := m.lookup(id); !errors.Is(err, ErrUploadNotFound) {
		t.Fatalf("session still present: %v", err)
	}
	// Idempotent: aborting again is a no-op.
	if err := m.Abort(id); err != nil {
		t.Fatalf("second Abort: %v", err)
	}
}

func TestEvictExpired(t *testing.T) {
	ttl := time.Minute
	m, err := NewManager(t.TempDir(), testCap, ttl, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	id, _ := m.Create("bucket", "key", Metadata{})
	dir := filepath.Join(m.baseDir, id)

	// Not yet expired.
	m.evictExpired(m.now())
	if _, err := m.lookup(id); err != nil {
		t.Fatalf("session evicted too early: %v", err)
	}

	// Past the TTL.
	m.evictExpired(time.Now().Add(2 * ttl))
	if _, err := m.lookup(id); !errors.Is(err, ErrUploadNotFound) {
		t.Fatalf("expired session not evicted: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("expired dir not removed: %v", err)
	}
}

func TestSweepOrphans(t *testing.T) {
	ttl := time.Minute
	m, err := NewManager(t.TempDir(), testCap, ttl, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// A live session's dir must survive the sweep.
	liveID, _ := m.Create("bucket", "key", Metadata{})

	// A stale orphan dir (unknown to the table, older than the TTL) must be removed.
	orphan := filepath.Join(m.baseDir, "orphan-upload")
	if err := os.MkdirAll(orphan, 0o700); err != nil {
		t.Fatalf("mkdir orphan: %v", err)
	}
	old := time.Now().Add(-2 * ttl)
	if err := os.Chtimes(orphan, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// A fresh orphan (younger than the TTL) must be left alone.
	freshOrphan := filepath.Join(m.baseDir, "fresh-orphan")
	if err := os.MkdirAll(freshOrphan, 0o700); err != nil {
		t.Fatalf("mkdir fresh orphan: %v", err)
	}

	m.sweepOrphans()

	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("stale orphan not swept: %v", err)
	}
	if _, err := os.Stat(freshOrphan); err != nil {
		t.Fatalf("fresh orphan wrongly swept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.baseDir, liveID)); err != nil {
		t.Fatalf("live session dir wrongly swept: %v", err)
	}
}

func TestConcurrentWritePartsDifferentParts(t *testing.T) {
	m := newTestManager(t)
	id, _ := m.Create("bucket", "key", Metadata{})

	var wg sync.WaitGroup
	for n := 1; n <= 8; n++ {
		wg.Add(1)
		go func(part int) {
			defer wg.Done()
			body := bytes.Repeat([]byte{byte('0' + part)}, 100)
			if _, err := m.WritePart(id, part, bytes.NewReader(body)); err != nil {
				t.Errorf("WritePart %d: %v", part, err)
			}
		}(n)
	}
	wg.Wait()

	data, _, err := m.Assemble(id, []int{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if len(data) != 800 {
		t.Fatalf("assembled size = %d, want 800", len(data))
	}
}

func TestMetricsInvoked(t *testing.T) {
	rec := &recordingMetrics{}
	m, err := NewManager(t.TempDir(), testCap, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)), rec)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	id, _ := m.Create("bucket", "key", Metadata{})
	if _, err := m.WritePart(id, 1, bytes.NewReader(bytes.Repeat([]byte("a"), 100))); err != nil {
		t.Fatalf("WritePart: %v", err)
	}
	if _, _, err := m.Assemble(id, []int{1}); err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if err := m.Abort(id); err != nil {
		t.Fatalf("Abort: %v", err)
	}

	if rec.uploadsActive != 0 {
		t.Errorf("uploadsActive = %v, want 0 (created then aborted)", rec.uploadsActive)
	}
	if rec.parts != 1 {
		t.Errorf("parts = %d, want 1", rec.parts)
	}
	if rec.bufferBytes != 0 {
		t.Errorf("bufferBytes = %v, want 0 after abort", rec.bufferBytes)
	}
	if rec.assembleObservations != 1 {
		t.Errorf("assembleObservations = %d, want 1", rec.assembleObservations)
	}
}

type recordingMetrics struct {
	mu                   sync.Mutex
	uploadsActive        float64
	parts                int
	bufferBytes          float64
	assembleObservations int
}

func (r *recordingMetrics) AddUploadsActive(delta float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.uploadsActive += delta
}

func (r *recordingMetrics) IncParts() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.parts++
}

func (r *recordingMetrics) AddBufferBytes(delta float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bufferBytes += delta
}

func (r *recordingMetrics) ObserveAssembleSeconds(float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.assembleObservations++
}
