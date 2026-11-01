package fsstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/PathOps/pathops-artifact-store/internal/key"
	"github.com/PathOps/pathops-artifact-store/internal/store"
)

const k = "applications/app-a/runs/r1/steps/WAIT_BUILD/attempts/1/bundle.tar.gz"

func open(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func TestPutGetStatDelete(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	ctx := context.Background()
	body := []byte("bundle bytes")
	info, created, err := s.Put(ctx, store.PutRequest{Key: k, MediaType: "application/gzip", Metadata: map[string]string{"a": "b"},
		CreatedBy: "system:serviceaccount:ns:sa", SHA256: digest(body)}, bytes.NewReader(body))
	if err != nil || !created || info.Size != int64(len(body)) || info.SHA256 != digest(body) {
		t.Fatal(info, created, err)
	}

	got, rc, err := s.Get(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(b, body) || got.MediaType != "application/gzip" || got.Metadata["a"] != "b" || got.CreatedBy != info.CreatedBy {
		t.Fatal(got)
	}

	// Durable: a new process (a restarted Pod) sees the same object.
	s.Close()
	s2 := open(t, dir)
	if st, err := s2.Stat(ctx, k); err != nil || st.SHA256 != info.SHA256 || !st.CreatedAt.Equal(info.CreatedAt) {
		t.Fatal(st, err)
	}

	// Same content again (a retry after a lost response): the same object.
	if again, created, err := s2.Put(ctx, store.PutRequest{Key: k}, bytes.NewReader(body)); err != nil || created || again.SHA256 != info.SHA256 {
		t.Fatal(again, created, err)
	}
	// Different content: immutable.
	if _, _, err := s2.Put(ctx, store.PutRequest{Key: k}, bytes.NewReader([]byte("other"))); !errors.Is(err, store.ErrExists) {
		t.Fatal(err)
	}

	if err := s2.Delete(ctx, k); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Stat(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if err := s2.Delete(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	// Empty directories are removed up to objects/.
	if entries, _ := os.ReadDir(filepath.Join(dir, "objects")); len(entries) != 0 {
		t.Fatal(entries)
	}
}

func TestPutRejects(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	ctx := context.Background()
	if _, _, err := s.Put(ctx, store.PutRequest{Key: k, SHA256: digest([]byte("x"))}, bytes.NewReader([]byte("y"))); !errors.Is(err, store.ErrDigestMismatch) {
		t.Fatal(err)
	}
	if _, err := s.Stat(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a rejected upload was stored")
	}
	for _, bad := range []string{"../escape", "a/../../escape", "/etc/passwd", "a/@data"} {
		if _, _, err := s.Put(ctx, store.PutRequest{Key: bad}, bytes.NewReader(nil)); !errors.Is(err, key.ErrInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
		if _, _, err := s.Get(ctx, bad); !errors.Is(err, key.ErrInvalid) {
			t.Errorf("get %q: %v", bad, err)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "escape")); !os.IsNotExist(err) {
		t.Fatal("escaped the root")
	}

	// A cancelled upload leaves nothing behind.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := s.Put(cctx, store.PutRequest{Key: k}, bytes.NewReader(make([]byte, 1<<20))); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "tmp")); len(entries) != 0 {
		t.Fatal("temporary upload left behind")
	}
}

// zeros is an endless reader that allocates nothing.
type zeros struct{ n int64 }

func (z *zeros) Read(p []byte) (int, error) {
	if z.n <= 0 {
		return 0, io.EOF
	}
	m := min(int64(len(p)), z.n)
	clear(p[:m])
	z.n -= m
	return int(m), nil
}

// TestStreaming writes and reads 256 MiB while allocating a small, constant
// amount: content is never held in memory.
func TestStreaming(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 256 MiB")
	}
	s := open(t, t.TempDir())
	ctx := context.Background()
	const size = 256 << 20
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if _, _, err := s.Put(ctx, store.PutRequest{Key: k}, &zeros{n: size}); err != nil {
		t.Fatal(err)
	}
	_, rc, err := s.Get(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.CopyBuffer(io.Discard, rc, make([]byte, 32<<10))
	rc.Close()
	runtime.ReadMemStats(&after)
	if err != nil || n != size {
		t.Fatal(n, err)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 4<<20 {
		t.Fatalf("allocated %d bytes for a %d-byte object", alloc, size)
	}
}
