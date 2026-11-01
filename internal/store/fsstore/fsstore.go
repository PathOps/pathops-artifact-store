// Package fsstore is the filesystem ArtifactStore backend (a PVC in a Cell).
//
// Layout under the root directory:
//
//	objects/<key>/@data        the content
//	objects/<key>/@meta.json   store.Info, written last: an object exists
//	                           once its metadata does
//	tmp/                       uploads in progress (same filesystem, so the
//	                           commit is a rename)
//
// "@" cannot start a key segment, so these names never collide with keys.
// Every access goes through an os.Root opened on the root directory: a path
// cannot escape it even if a key check were wrong. Content is streamed in
// fixed-size buffers and synced to disk before the commit.
package fsstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sync"
	"time"

	"github.com/PathOps/pathops-artifact-store/internal/key"
	"github.com/PathOps/pathops-artifact-store/internal/store"
)

const (
	dataName = "@data"
	metaName = "@meta.json"
)

// Store is a filesystem ArtifactStore.
type Store struct {
	root *os.Root
	now  func() time.Time
	mu   sync.Mutex // commit and delete
}

var _ store.ArtifactStore = (*Store)(nil)

// Open uses dir (created if missing) and removes uploads left by a previous
// process.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	if err := root.RemoveAll("tmp"); err != nil {
		root.Close()
		return nil, err
	}
	for _, d := range []string{"objects", "tmp"} {
		if err := root.MkdirAll(d, 0o700); err != nil {
			root.Close()
			return nil, err
		}
	}
	return &Store{root: root, now: time.Now}, nil
}

// Close releases the root directory.
func (s *Store) Close() error { return s.root.Close() }

func objectDir(k string) string { return path.Join("objects", k) }

// Put implements store.ArtifactStore.
func (s *Store) Put(ctx context.Context, req store.PutRequest, content io.Reader) (store.Info, bool, error) {
	if err := key.Validate(req.Key); err != nil {
		return store.Info{}, false, err
	}
	tmp, f, err := s.tempFile()
	if err != nil {
		return store.Info{}, false, err
	}
	defer s.root.Remove(tmp) // no-op after the commit renamed it
	h := sha256.New()
	n, err := copyContext(ctx, io.MultiWriter(f, h), content)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return store.Info{}, false, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if req.SHA256 != "" && req.SHA256 != sum {
		return store.Info{}, false, store.ErrDigestMismatch
	}
	info := store.Info{Key: req.Key, Size: n, SHA256: sum, MediaType: req.MediaType, Metadata: req.Metadata,
		CreatedAt: s.now().UTC().Truncate(time.Millisecond), CreatedBy: req.CreatedBy}
	meta, err := json.Marshal(info)
	if err != nil {
		return store.Info{}, false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if old, err := s.stat(req.Key); err == nil {
		if old.SHA256 == sum && old.Size == n {
			return old, false, nil
		}
		return store.Info{}, false, store.ErrExists
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.Info{}, false, err
	}
	dir := objectDir(req.Key)
	if err := s.root.MkdirAll(dir, 0o700); err != nil {
		return store.Info{}, false, err
	}
	if err := s.root.Rename(tmp, path.Join(dir, dataName)); err != nil {
		return store.Info{}, false, err
	}
	if err := s.writeFileSynced(path.Join(dir, metaName), meta); err != nil {
		return store.Info{}, false, err
	}
	return info, true, s.syncDir(dir)
}

// Get implements store.ArtifactStore.
func (s *Store) Get(_ context.Context, k string) (store.Info, io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock() // only while opening: an open file survives a delete
	info, err := s.stat(k)
	if err != nil {
		return store.Info{}, nil, err
	}
	f, err := s.root.Open(path.Join(objectDir(k), dataName))
	if err != nil {
		return store.Info{}, nil, err
	}
	return info, f, nil
}

// Stat implements store.ArtifactStore.
func (s *Store) Stat(_ context.Context, k string) (store.Info, error) {
	return s.stat(k)
}

// Delete implements store.ArtifactStore. The metadata goes first, so a
// half-deleted object no longer exists.
func (s *Store) Delete(_ context.Context, k string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.stat(k); err != nil {
		return err
	}
	dir := objectDir(k)
	if err := s.root.Remove(path.Join(dir, metaName)); err != nil {
		return err
	}
	if err := s.root.Remove(path.Join(dir, dataName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	s.removeEmptyParents(dir)
	return nil
}

func (s *Store) stat(k string) (store.Info, error) {
	if err := key.Validate(k); err != nil {
		return store.Info{}, err
	}
	b, err := s.root.ReadFile(path.Join(objectDir(k), metaName))
	if errors.Is(err, fs.ErrNotExist) {
		return store.Info{}, store.ErrNotFound
	}
	if err != nil {
		return store.Info{}, err
	}
	var info store.Info
	if err := json.Unmarshal(b, &info); err != nil {
		return store.Info{}, fmt.Errorf("corrupt metadata of %s: %w", k, err)
	}
	return info, nil
}

func (s *Store) tempFile() (string, *os.File, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	name := path.Join("tmp", hex.EncodeToString(b))
	f, err := s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	return name, f, err
}

func (s *Store) writeFileSynced(name string, b []byte) error {
	tmp, f, err := s.tempFile()
	if err != nil {
		return err
	}
	defer s.root.Remove(tmp)
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return s.root.Rename(tmp, name)
}

func (s *Store) syncDir(dir string) error {
	d, err := s.root.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// removeEmptyParents removes now-empty directories up to objects/.
func (s *Store) removeEmptyParents(dir string) {
	for dir != "objects" && dir != "." {
		if s.root.Remove(dir) != nil { // fails when not empty
			return
		}
		dir = path.Dir(dir)
	}
}

// copyContext copies in 32 KiB chunks and stops when ctx is done.
func copyContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 32<<10)
	var n int64
	for {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		r, err := src.Read(buf)
		if r > 0 {
			w, werr := dst.Write(buf[:r])
			n += int64(w)
			if werr != nil {
				return n, werr
			}
		}
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
	}
}
