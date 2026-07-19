package workflow

import (
	"bytes"
	"testing"

	"github.com/go-ctap/ctap/protocol"
	appcredentials "github.com/go-ctap/kit/model/credentials"
)

func TestLargeBlobStateRetainsInventory(t *testing.T) {
	blobs := []protocol.LargeBlob{{Ciphertext: []byte{0x01}}}
	inventory := &largeBlobInventory{blobs: blobs}
	state := NewLargeBlobState()
	state.replaceInventory(inventory)

	loaded, ok := state.currentInventory()
	if !ok {
		t.Fatal("large blob inventory missing")
	}
	if loaded != inventory {
		t.Fatal("large blob inventory was copied")
	}
	if &loaded.blobs[0] != &blobs[0] {
		t.Fatal("large blob array was copied")
	}

	replacement := []protocol.LargeBlob{{Ciphertext: []byte{0x02}}}
	state.replaceBlobs(replacement)
	if &state.current.blobs[0] != &replacement[0] {
		t.Fatal("replacement large blob array was copied")
	}
}

func TestLargeBlobStateClearZerosOwnedKeys(t *testing.T) {
	state := NewLargeBlobState()
	state.replaceInventory(&largeBlobInventory{
		credentials: appcredentials.InventoryReport{
			Groups: []appcredentials.CredentialGroup{{
				Credentials: []appcredentials.CredentialRecord{{
					LargeBlobKey: bytes.Repeat([]byte{0x11}, 32),
				}},
			}},
		},
	})

	key := state.current.credentials.Groups[0].Credentials[0].LargeBlobKey
	state.Clear()

	if state.current != nil {
		t.Fatal("large blob inventory retained after clear")
	}
	if !bytes.Equal(key, make([]byte, len(key))) {
		t.Fatal("largeBlobKey was not zeroed")
	}
}
