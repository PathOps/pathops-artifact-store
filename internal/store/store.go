// Package store defines the ArtifactStore abstraction. The HTTP service and
// its clients depend on this interface only; a filesystem backend
// (fsstore) is the first implementation and an S3-compatible one can replace
// it without changing them.
//
// Objects are immutable: a key is written once. Content is opaque bytes plus
// a media type, size, SHA-256 and small string metadata.
package store

import (
	"context"
	"errors"
	"io"
	"time"
)

var (
	// ErrNotFound: no object has the key.
	ErrNotFound = errors.New("object not found")
	// ErrExists: another object already has the key.
	ErrExists = errors.New("object exists with different content")
	// ErrDigestMismatch: the content does not have the SHA-256 the writer declared.
	ErrDigestMismatch = errors.New("content does not match the declared sha256")
)

// Info describes a stored object.
type Info struct {
	Key       string            `json:"key"`
	Size      int64             `json:"size"`
	SHA256    string            `json:"sha256"` // lowercase hex
	MediaType string            `json:"mediaType"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"createdAt"`
	CreatedBy string            `json:"createdBy"`
}

// PutRequest describes an object to write; its content is the reader passed
// with it.
type PutRequest struct {
	Key       string
	MediaType string
	Metadata  map[string]string
	CreatedBy string
	// SHA256, if set (lowercase hex), must match the content.
	SHA256 string
}

// ArtifactStore stores immutable objects by key.
type ArtifactStore interface {
	// Put streams content to the key. If the key already holds identical
	// content (same SHA-256 and size), it returns that object and created
	// false, so a writer may retry after a lost response; different content
	// is ErrExists.
	Put(ctx context.Context, req PutRequest, content io.Reader) (info Info, created bool, err error)
	// Get opens the object for streaming; the caller closes it.
	Get(ctx context.Context, key string) (Info, io.ReadCloser, error)
	// Stat describes the object.
	Stat(ctx context.Context, key string) (Info, error)
	// Delete removes the object; ErrNotFound if there is none.
	Delete(ctx context.Context, key string) error
}
