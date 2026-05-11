package ctapkit

import (
	"context"
	"errors"
	"net/http"

	rtmds "github.com/go-ctap/kit/internal/mds"
	"github.com/go-ctap/kit/model"
	appmds "github.com/go-ctap/kit/model/mds"
	"github.com/google/uuid"
)

// MDSOption configures a FIDO Metadata Service lookup.
type MDSOption func(*mdsConfig)

type mdsConfig struct {
	source     string
	httpClient *http.Client
	cache      rtmds.Cache
	cacheDir   string
	refresh    bool
}

var defaultMDSCache = rtmds.NewCache()

// WithMDSSource overrides the default FIDO MDS3 blob URL.
func WithMDSSource(url string) MDSOption {
	return func(config *mdsConfig) {
		config.source = url
	}
}

// WithMDSHTTPClient overrides the HTTP client used to fetch the MDS3 blob.
func WithMDSHTTPClient(client *http.Client) MDSOption {
	return func(config *mdsConfig) {
		config.httpClient = client
	}
}

func WithMDSCache(cache rtmds.Cache) MDSOption {
	return func(config *mdsConfig) {
		config.cache = cache
	}
}

// WithMDSCacheDir overrides the directory used for the verified MDS blob cache.
func WithMDSCacheDir(path string) MDSOption {
	return func(config *mdsConfig) {
		config.cacheDir = path
	}
}

// WithMDSRefresh bypasses the in-memory and filesystem MDS caches for one lookup.
func WithMDSRefresh() MDSOption {
	return func(config *mdsConfig) {
		config.refresh = true
	}
}

// LookupMDS returns verified FIDO Metadata Service data for an AAGUID.
func LookupMDS(ctx context.Context, aaguid uuid.UUID, opts ...MDSOption) (appmds.LookupResult, error) {
	return lookupMDS(ctx, aaguid, opts...)
}

func lookupMDS(
	ctx context.Context,
	aaguid uuid.UUID,
	opts ...MDSOption,
) (appmds.LookupResult, error) {
	var config mdsConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&config)
		}
	}

	client := &rtmds.Client{
		Source:     config.source,
		HTTPClient: config.httpClient,
		Cache:      config.cache,
		CacheDir:   config.cacheDir,
	}
	result, err := client.Lookup(ctx, aaguid, rtmds.LookupOptions{Refresh: config.refresh})
	if err != nil {
		return appmds.LookupResult{}, runtimeMDSError(err)
	}

	return result, nil
}

func runtimeMDSError(err error) error {
	switch {
	case errors.Is(err, rtmds.ErrInvalidAAGUID):
		return model.NewRuntimeError(model.ErrorInvalidOperation, err.Error(), err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return model.NewRuntimeError(model.ErrorCanceled, "MDS lookup canceled", err)
	case errors.Is(err, rtmds.ErrFetch):
		return model.NewRuntimeError(model.ErrorTransportFailure, err.Error(), err)
	case errors.Is(err, rtmds.ErrVerify):
		return model.NewRuntimeError(model.ErrorInvalidState, err.Error(), err)
	default:
		return err
	}
}
