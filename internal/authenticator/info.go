package authenticator

import (
	"context"

	"github.com/go-ctap/ctap/protocol"
)

// ResolveInfo returns the valid cached getInfo response or refreshes it when
// the authenticator has invalidated its cache.
func ResolveInfo(ctx context.Context, provider InfoProvider) (protocol.AuthenticatorGetInfoResponse, error) {
	if info, valid := provider.GetInfoCached(); valid {
		return info, nil
	}

	return provider.GetInfo(ctx)
}
