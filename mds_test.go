package ctapkit

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/go-ctap/kit/model/failure"
	"github.com/google/uuid"
)

type mdsRoundTripper func(*http.Request) (*http.Response, error)

func (f mdsRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestLookupMDSUsesConfiguredClientAndNormalizesHTTPStatus(t *testing.T) {
	const source = "https://mds.example.test/"

	client := &http.Client{Transport: mdsRoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != source {
			t.Fatalf("request URL = %q, want %q", request.URL, source)
		}

		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}

	_, err := LookupMDS(
		context.Background(),
		uuid.MustParse("eabb46cc-e241-80bf-ae9e-96fa6d2975cf"),
		WithMDSSource(source),
		WithMDSHTTPClient(client),
		WithMDSCacheDir(t.TempDir()),
		WithMDSRefresh(),
	)
	if !failure.IsCode(err, failure.CodeMDSFetchFailed) {
		t.Fatalf("LookupMDS error = %v, want %s", err, failure.CodeMDSFetchFailed)
	}

	snapshot := failure.Snapshot(err)
	if snapshot.Params["httpStatus"] != "429" {
		t.Fatalf("LookupMDS params = %#v, want httpStatus 429", snapshot.Params)
	}
}
