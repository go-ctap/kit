package mds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	appmds "github.com/go-ctap/kit/model/mds"
	"github.com/google/uuid"
)

func TestLookupRevalidationMarksDiskCacheFresh(t *testing.T) {
	now := time.Date(2026, time.July, 10, 12, 0, 0, 0, time.UTC)
	old := now.Add(-48 * time.Hour)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	t.Cleanup(server.Close)

	client := &Client{
		Source:   server.URL,
		Cache:    NewCache(),
		CacheDir: t.TempDir(),
		Now:      func() time.Time { return now },
	}
	aaguid := uuid.New()
	client.Cache.Set(client.cacheKey(server.URL), &Blob{
		Number:   1,
		Entries:  map[uuid.UUID]appmds.PayloadEntry{},
		CachedAt: old,
	})

	path, err := client.diskCachePath(server.URL)
	if err != nil {
		t.Fatalf("disk cache path: %v", err)
	}
	if err := os.WriteFile(path, []byte("cached"), 0o600); err != nil {
		t.Fatalf("write disk cache: %v", err)
	}
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("age disk cache: %v", err)
	}

	if _, err := client.Lookup(context.Background(), aaguid, LookupOptions{}); err != nil {
		t.Fatalf("lookup: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat disk cache: %v", err)
	}
	if got := info.ModTime(); !got.Equal(now) {
		t.Fatalf("disk cache modtime = %v, want %v", got, now)
	}
}

func TestLookupAllowsVerifiedStaleCacheOnRateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(server.Close)

	now := time.Date(2026, time.July, 10, 12, 0, 0, 0, time.UTC)
	client := &Client{
		Source: server.URL,
		Cache:  NewCache(),
		Now:    func() time.Time { return now },
	}
	aaguid := uuid.New()
	client.Cache.Set(client.cacheKey(server.URL), &Blob{
		Number:   1,
		Entries:  map[uuid.UUID]appmds.PayloadEntry{},
		CachedAt: now.Add(-48 * time.Hour),
	})

	result, err := client.Lookup(context.Background(), aaguid, LookupOptions{
		AllowStaleOnFetchError: true,
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !result.Cached {
		t.Fatal("lookup did not report the stale verified cache")
	}
}
