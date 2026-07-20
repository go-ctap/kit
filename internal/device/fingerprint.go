package device

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/go-ctap/kit/transport"
)

const fingerprintLength = 16

// Fingerprint returns an opaque identifier for one discovered authenticator.
// A serial-backed fingerprint follows the device across transport path changes;
// devices without a reported serial fall back to their current attachment.
func Fingerprint(mode transport.Mode, descriptor transport.Descriptor) string {
	seed := fingerprintSeed(mode, descriptor)
	sum := sha256.Sum256([]byte(seed))

	return hex.EncodeToString(sum[:])[:fingerprintLength]
}

func fingerprintSeed(mode transport.Mode, descriptor transport.Descriptor) string {
	parts := []string{
		"ctapkit-fingerprint-v1",
		fmt.Sprintf("%04x", descriptor.VendorID),
		fmt.Sprintf("%04x", descriptor.ProductID),
	}

	serial := strings.TrimSpace(descriptor.Serial)
	if serial != "" {
		return strings.Join(append(parts, "serial", serial), "\x00")
	}

	return strings.Join(append(parts, "path", string(mode), strings.TrimSpace(descriptor.Path)), "\x00")
}
