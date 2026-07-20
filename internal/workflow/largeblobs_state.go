package workflow

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/errornorm"
	"github.com/go-ctap/kit/internal/secret"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/failure"
)

// LargeBlobState owns the inventory loaded for the selected authenticator.
// Authenticator operations are serialized, so every large-blob operation uses
// this state directly until the next list or authenticator close.
type LargeBlobState struct {
	current *largeBlobInventory
}

type largeBlobKeyID struct {
	rpIDHashHex     string
	credentialIDHex string
}

// largeBlobKeyStore owns key buffers returned by credential enumeration.
type largeBlobKeyStore map[largeBlobKeyID][]byte

type largeBlobInventory struct {
	credentials appcredentials.InventoryReport
	keys        largeBlobKeyStore
	blobs       []protocol.LargeBlob
}

func NewLargeBlobState() *LargeBlobState {
	return &LargeBlobState{}
}

func (r Runner) loadLargeBlobInventory(
	ctx context.Context,
	device LargeBlobDevice,
	state *LargeBlobState,
	grantPermission protocol.Permission,
) (*largeBlobInventory, error) {
	if err := ctx.Err(); err != nil {
		return nil, errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseDiscovery))
	}

	if inventory, ok := state.currentInventory(); ok {
		return inventory, nil
	}

	return r.refreshLargeBlobInventory(ctx, device, state, grantPermission)
}

func (r Runner) refreshLargeBlobInventory(
	ctx context.Context,
	device LargeBlobDevice,
	state *LargeBlobState,
	grantPermission protocol.Permission,
) (*largeBlobInventory, error) {
	keys := make(largeBlobKeyStore)
	credentials, err := r.credentialInventory(ctx, device, grantPermission, keys)
	if err != nil {
		return nil, err
	}

	inventory := &largeBlobInventory{
		credentials: credentials,
		keys:        keys,
	}
	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		inventory.clear()
		return nil, err
	}
	support := buildLargeBlobSupportReport(info)
	if support.LargeBlobs {
		inventory.blobs, err = r.readLargeBlobArray(ctx, device)
		if err != nil {
			inventory.clear()

			return nil, err
		}
	}

	state.replaceInventory(inventory)

	return inventory, nil
}

func (state *LargeBlobState) currentInventory() (*largeBlobInventory, bool) {
	if state == nil || state.current == nil {
		return nil, false
	}

	return state.current, true
}

func (state *LargeBlobState) replaceInventory(inventory *largeBlobInventory) {
	if state == nil {
		return
	}

	state.Clear()
	state.current = inventory
}

func (state *LargeBlobState) replaceBlobs(blobs []protocol.LargeBlob) {
	if state == nil || state.current == nil {
		return
	}

	state.current.blobs = blobs
}

// Clear releases the credential keys retained for the selected authenticator.
func (state *LargeBlobState) Clear() {
	if state == nil || state.current == nil {
		return
	}

	state.current.clear()
	state.current = nil
}

func (inventory *largeBlobInventory) clear() {
	if inventory == nil {
		return
	}

	inventory.keys.zero()
	inventory.keys = nil
	inventory.blobs = nil
}

func (keys largeBlobKeyStore) add(rpIDHashHex, credentialIDHex string, key []byte) {
	keyID := largeBlobKeyID{
		rpIDHashHex:     rpIDHashHex,
		credentialIDHex: credentialIDHex,
	}
	if _, exists := keys[keyID]; exists {
		secret.Zero(key)

		return
	}

	keys[keyID] = key
}

func (keys largeBlobKeyStore) get(rpIDHashHex, credentialIDHex string) []byte {
	return keys[largeBlobKeyID{
		rpIDHashHex:     rpIDHashHex,
		credentialIDHex: credentialIDHex,
	}]
}

func (keys largeBlobKeyStore) zero() {
	for keyID, key := range keys {
		secret.Zero(key)
		delete(keys, keyID)
	}
}
