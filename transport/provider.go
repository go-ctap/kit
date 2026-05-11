package transport

import (
	"context"
	"errors"
)

type Mode string

const (
	ModeAuto         Mode = "auto"
	ModeHID          Mode = "hid"
	ModeWindowsProxy Mode = "windows-proxy"
)

var (
	ErrUnsupportedMode  = errors.New("ctapkit: unsupported transport mode")
	ErrPermissionDenied = errors.New("ctapkit: transport permission denied")
	ErrProxyUnavailable = errors.New("ctapkit: transport proxy unavailable")
)

// Descriptor is the transport-layer view of a reachable authenticator.
type Descriptor struct {
	Transport    Mode
	Path         string
	Manufacturer string
	Product      string
	Serial       string
	VendorID     uint16
	ProductID    uint16
	UsagePage    uint16
	Usage        uint16
}

// Provider enumerates authenticators for one resolved transport mode.
type Provider interface {
	Check(ctx context.Context) error
	List(ctx context.Context) ([]Descriptor, error)
}

// ProviderResolver resolves the transport provider that should service a command.
type ProviderResolver interface {
	Resolve(ctx context.Context, requested Mode) (ResolvedProvider, error)
}

// ResolvedProvider captures the effective transport after policy resolution.
type ResolvedProvider struct {
	Mode     Mode
	Provider Provider
}
