package ctapkit

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
)

func TestLookupMDS(t *testing.T) {
	res, err := LookupMDS(context.Background(), uuid.MustParse("eabb46cc-e241-80bf-ae9e-96fa6d2975cf"))
	if err != nil {
		t.Fatalf("cannot lookup mds: %v", err)
	}
	if !res.Found || res.Entry == nil {
		t.Fatalf("MDS entry not found for %s", res.AAGUID)
	}

	b, _ := json.MarshalIndent(res.Entry.MetadataStatement, "", "  ")
	fmt.Println(string(b))

	res2, err := LookupMDS(context.Background(), uuid.MustParse("eabb46cc-e241-80bf-ae9e-96fa6d2975cf"))
	if err != nil {
		t.Fatalf("cannot lookup mds: %v", err)
	}
	_ = res2
}
