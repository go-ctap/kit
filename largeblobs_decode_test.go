package ctapkit

import (
	"reflect"
	"testing"

	"github.com/go-ctap/kit/model/failure"
	"github.com/go-ctap/kit/model/largeblobs"
)

func TestDecodeLargeBlobReturnsZeroResultOnError(t *testing.T) {
	result, err := DecodeLargeBlob([]byte(`{"broken"`), largeblobs.DecodeModeJSON)
	if !failure.IsCode(err, failure.CodeLargeBlobJSONInvalid) {
		t.Fatalf("DecodeLargeBlob error = %v, want %s", err, failure.CodeLargeBlobJSONInvalid)
	}
	if !reflect.DeepEqual(result, largeblobs.DecodeResult{}) {
		t.Fatalf("DecodeLargeBlob result = %#v, want zero", result)
	}
}
