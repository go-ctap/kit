package workflow

import (
	"testing"

	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	"github.com/go-ctap/kit/internal/secret"
	rtsession "github.com/go-ctap/kit/internal/session"
	"github.com/go-ctap/kit/model"
	appconfig "github.com/go-ctap/kit/model/config"
	appcredentials "github.com/go-ctap/kit/model/credentials"
	applargeblobs "github.com/go-ctap/kit/model/largeblobs"
	"github.com/go-ctap/kit/model/report"
)

func TestInvalidateCachesAfterUsesDomainPolicy(t *testing.T) {
	tests := []struct {
		name            string
		operation       model.Operation
		wantCredentials bool
		wantLargeBlobs  bool
		wantConfig      bool
	}{
		{
			name:            "read operation keeps snapshots",
			operation:       model.ConfigStatusOperation{},
			wantCredentials: true,
			wantLargeBlobs:  true,
			wantConfig:      true,
		},
		{
			name:           "credential mutation invalidates credentials and dependent blob lists",
			operation:      model.DeleteCredentialOperation{},
			wantConfig:     true,
			wantLargeBlobs: false,
		},
		{
			name:            "large blob mutation keeps credential inventory",
			operation:       model.WriteLargeBlobOperation{},
			wantCredentials: true,
			wantConfig:      true,
		},
		{
			name:            "config mutation keeps credential and blob snapshots",
			operation:       model.SetAlwaysUVOperation{},
			wantCredentials: true,
			wantLargeBlobs:  true,
			wantConfig:      false,
		},
		{
			name:            "bio rename keeps config snapshot",
			operation:       model.BioRenameOperation{},
			wantCredentials: true,
			wantLargeBlobs:  true,
			wantConfig:      true,
		},
		{
			name:            "bio enroll invalidates config snapshot",
			operation:       model.BioEnrollOperation{},
			wantCredentials: true,
			wantLargeBlobs:  true,
			wantConfig:      false,
		},
		{
			name:      "reset invalidates every snapshot",
			operation: model.ResetFactoryOperation{},
		},
		{
			name:            "dry run mutation keeps snapshots",
			operation:       model.DeleteLargeBlobOperation{DryRun: true},
			wantCredentials: true,
			wantLargeBlobs:  true,
			wantConfig:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := rtsession.New(nil, report.DeviceReport{}, nil, nil, false)
			cache := session.Cache()
			cache.SetCredential(appcredentials.InventoryReport{})
			cache.SetLargeBlobList(applargeblobs.ListReport{})
			cache.SetConfig(appconfig.StatusReport{})

			testEffectsForOperation(tt.operation).Apply(cache)

			if _, got := cache.Credential(); got != tt.wantCredentials {
				t.Fatalf("credential cache present = %v, want %v", got, tt.wantCredentials)
			}

			if _, got := cache.LargeBlobList(); got != tt.wantLargeBlobs {
				t.Fatalf("large blob cache present = %v, want %v", got, tt.wantLargeBlobs)
			}

			if _, got := cache.Config(); got != tt.wantConfig {
				t.Fatalf("config cache present = %v, want %v", got, tt.wantConfig)
			}
		})
	}
}

func TestLargeBlobResultEffectsOnlyInvalidateAfterRealMutation(t *testing.T) {
	tests := []struct {
		name   string
		effect Effects
		want   bool
	}{
		{
			name: "delete no blob keeps report",
			effect: largeBlobMutationResultEffects(model.DeleteLargeBlobOperation{}, model.LargeBlobMutationOutput{
				Result: &applargeblobs.MutationResult{NoBlob: true},
			}),
			want: true,
		},
		{
			name: "delete existing blob invalidates report",
			effect: largeBlobMutationResultEffects(model.DeleteLargeBlobOperation{}, model.LargeBlobMutationOutput{
				Result: &applargeblobs.MutationResult{},
			}),
		},
		{
			name: "garbage collect noop keeps report",
			effect: largeBlobMutationResultEffects(model.GarbageCollectLargeBlobsOperation{}, model.LargeBlobMutationOutput{
				Result: &applargeblobs.MutationResult{Noop: true},
			}),
			want: true,
		},
		{
			name: "garbage collect deletion invalidates report",
			effect: largeBlobMutationResultEffects(model.GarbageCollectLargeBlobsOperation{}, model.LargeBlobMutationOutput{
				Result: &applargeblobs.MutationResult{DeletedBlobCount: 1},
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := rtsession.New(nil, report.DeviceReport{}, nil, nil, false)
			cache := session.Cache()
			cache.SetLargeBlobList(applargeblobs.ListReport{})

			tt.effect.Apply(cache)

			if _, got := cache.LargeBlobList(); got != tt.want {
				t.Fatalf("large blob cache present = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInvalidateCachesAfterUsesTokenPolicy(t *testing.T) {
	tests := []struct {
		name      string
		operation model.Operation
		key       rtsession.TokenKey
		want      bool
	}{
		{
			name:      "read operation keeps token",
			operation: model.ConfigStatusOperation{},
			key:       rtsession.TokenKey{Permission: ctaptypes.PermissionCredentialManagement},
			want:      true,
		},
		{
			name:      "pin mutation invalidates all tokens",
			operation: model.ChangePINOperation{},
			key:       rtsession.TokenKey{Permission: ctaptypes.PermissionCredentialManagement},
		},
		{
			name:      "bio rename keeps bio token",
			operation: model.BioRenameOperation{},
			key:       rtsession.TokenKey{Permission: ctaptypes.PermissionBioEnrollment},
			want:      true,
		},
		{
			name:      "bio enroll keeps bio token",
			operation: model.BioEnrollOperation{},
			key:       rtsession.TokenKey{Permission: ctaptypes.PermissionBioEnrollment},
			want:      true,
		},
		{
			name:      "bio remove keeps credential token",
			operation: model.BioRemoveOperation{},
			key:       rtsession.TokenKey{Permission: ctaptypes.PermissionCredentialManagement},
			want:      true,
		},
		{
			name:      "authenticator config mutation keeps config token",
			operation: model.SetAlwaysUVOperation{},
			key:       rtsession.TokenKey{Permission: ctaptypes.PermissionAuthenticatorConfiguration},
			want:      true,
		},
		{
			name:      "authenticator config mutation keeps bio token",
			operation: model.SetAlwaysUVOperation{},
			key:       rtsession.TokenKey{Permission: ctaptypes.PermissionBioEnrollment},
			want:      true,
		},
		{
			name:      "large blob mutation keeps token",
			operation: model.WriteLargeBlobOperation{},
			key:       rtsession.TokenKey{Permission: ctaptypes.PermissionCredentialManagement},
			want:      true,
		},
		{
			name:      "dry run mutation keeps token",
			operation: model.BioRemoveOperation{DryRun: true},
			key:       rtsession.TokenKey{Permission: ctaptypes.PermissionBioEnrollment},
			want:      true,
		},
		{
			name:      "reset invalidates token",
			operation: model.ResetFactoryOperation{},
			key:       rtsession.TokenKey{Permission: ctaptypes.PermissionCredentialManagement},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := rtsession.New(nil, report.DeviceReport{}, nil, nil, false)
			cache := session.Cache()
			cache.SetToken(tt.key, secret.New([]byte("token")))

			testEffectsForOperation(tt.operation).Apply(cache)

			assertTokenPresent(t, cache, tt.key, tt.want)
		})
	}
}

func TestUserPresenceTokenEffectsClearsPermissionsExceptLargeBlobWrite(t *testing.T) {
	tests := []struct {
		name        string
		key         rtsession.TokenKey
		userPresent bool
		want        bool
	}{
		{
			name:        "successful user presence clears credential token",
			key:         rtsession.TokenKey{Permission: ctaptypes.PermissionCredentialManagement},
			userPresent: true,
		},
		{
			name:        "successful user presence preserves large blob write token",
			key:         rtsession.TokenKey{Permission: ctaptypes.PermissionLargeBlobWrite},
			userPresent: true,
			want:        true,
		},
		{
			name:        "operation without user presence leaves token untouched",
			key:         rtsession.TokenKey{Permission: ctaptypes.PermissionCredentialManagement},
			userPresent: false,
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := rtsession.New(nil, report.DeviceReport{}, nil, nil, false)
			cache := session.Cache()
			cache.SetToken(tt.key, secret.New([]byte("token")))

			Effects{ClearTokenUnlessLargeBlobWrite: tt.userPresent}.Apply(cache)

			assertTokenPresent(t, cache, tt.key, tt.want)
		})
	}
}

func assertTokenPresent(t *testing.T, cache *rtsession.Cache, key rtsession.TokenKey, want bool) {
	t.Helper()

	_, got, err := cache.GetToken(key)
	if err != nil {
		t.Fatalf("token get for %+v: %v", key, err)
	}

	if got != want {
		t.Fatalf("token present for %+v = %v, want %v", key, got, want)
	}
}

func testEffectsForOperation(operation model.Operation) Effects {
	switch op := operation.(type) {
	case model.DeleteCredentialOperation:
		return credentialMutationEffects(op)
	case model.UpdateCredentialUserOperation:
		return credentialMutationEffects(op)
	case model.WriteLargeBlobOperation:
		return largeBlobMutationEffects(op)
	case model.DeleteLargeBlobOperation:
		return largeBlobMutationEffects(op)
	case model.GarbageCollectLargeBlobsOperation:
		return largeBlobMutationEffects(op)
	case model.ResetFactoryOperation:
		return resetEffects(op)
	case model.SetPINOperation:
		return pinMutationEffects(op)
	case model.ChangePINOperation:
		return pinMutationEffects(op)
	case model.BioEnrollOperation:
		return bioMutationEffects(op)
	case model.BioRenameOperation:
		return Effects{}
	case model.BioRemoveOperation:
		return bioMutationEffects(op)
	case model.SetAlwaysUVOperation:
		return authenticatorConfigEffects(op)
	case model.SetMinPINLengthOperation:
		return authenticatorConfigEffects(op)
	default:
		return Effects{}
	}
}
