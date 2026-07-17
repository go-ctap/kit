package mds

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	appmds "github.com/go-ctap/kit/model/mds"
	"github.com/google/uuid"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func statusTransport(status int) http.RoundTripper {
	return roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       http.NoBody,
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})
}

func TestLookupRevalidationMarksDiskCacheFresh(t *testing.T) {
	const source = "https://mds.example.test/revalidation"

	now := time.Date(2026, time.July, 10, 12, 0, 0, 0, time.UTC)
	old := now.Add(-48 * time.Hour)

	client := &Client{
		Source:     source,
		HTTPClient: &http.Client{Transport: statusTransport(http.StatusNotModified)},
		Cache:      NewCache(),
		CacheDir:   t.TempDir(),
		Now:        func() time.Time { return now },
	}
	aaguid := uuid.New()
	client.Cache.Set(client.cacheKey(source), &Blob{
		Number:   1,
		Entries:  map[uuid.UUID]appmds.PayloadEntry{},
		CachedAt: old,
	})

	path, err := client.diskCachePath(source)
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
	const source = "https://mds.example.test/rate-limit"

	now := time.Date(2026, time.July, 10, 12, 0, 0, 0, time.UTC)
	client := &Client{
		Source:     source,
		HTTPClient: &http.Client{Transport: statusTransport(http.StatusTooManyRequests)},
		Cache:      NewCache(),
		Now:        func() time.Time { return now },
	}
	aaguid := uuid.New()
	client.Cache.Set(client.cacheKey(source), &Blob{
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

func TestLookupKeepsDiskCacheWhenVerificationFails(t *testing.T) {
	const source = "https://mds.example.test/invalid-cache"

	client := &Client{
		Source:     source,
		HTTPClient: &http.Client{Transport: statusTransport(http.StatusServiceUnavailable)},
		Cache:      NewCache(),
		CacheDir:   t.TempDir(),
	}
	path, err := client.diskCachePath(source)
	if err != nil {
		t.Fatalf("disk cache path: %v", err)
	}
	cached := []byte("cached blob awaiting successful revalidation")
	if err := os.WriteFile(path, cached, 0o600); err != nil {
		t.Fatalf("write disk cache: %v", err)
	}

	_, err = client.Lookup(context.Background(), uuid.New(), LookupOptions{
		AllowStaleOnFetchError: true,
	})
	if !errors.Is(err, ErrFetch) {
		t.Fatalf("lookup error = %v, want %v", err, ErrFetch)
	}

	retained, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read retained disk cache: %v", err)
	}
	if !bytes.Equal(retained, cached) {
		t.Fatalf("retained disk cache = %q, want %q", retained, cached)
	}
}
