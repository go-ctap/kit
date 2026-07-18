package mds

import "sync"

// Cache stores and shares verified MDS blobs in process memory.
type Cache interface {
	Get(source string) (*Blob, bool)
	Set(source string, blob *Blob)
}

type simpleCache struct {
	mu    sync.RWMutex
	blobs map[string]*Blob
}

// NewCache creates a process-local MDS blob cache.
func NewCache() Cache {
	return &simpleCache{blobs: make(map[string]*Blob)}
}

func (c *simpleCache) Get(source string) (*Blob, bool) {
	c.mu.RLock()
	blob, ok := c.blobs[source]
	c.mu.RUnlock()

	return blob, ok
}

func (c *simpleCache) Set(source string, blob *Blob) {
	if blob == nil {
		return
	}

	c.mu.Lock()
	c.blobs[source] = blob
	c.mu.Unlock()
}
