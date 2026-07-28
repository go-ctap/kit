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
func Fingerprint(descriptor transport.Descriptor) string {
	seed := fingerprintSeed(descriptor)
	sum := sha256.Sum256([]byte(seed))

	return hex.EncodeToString(sum[:])[:fingerprintLength]
}

func fingerprintSeed(descriptor transport.Descriptor) string {
	parts := []string{
		"ctapkit-fingerprint-v1",
		fmt.Sprintf("%04x", descriptor.VendorID),
		fmt.Sprintf("%04x", descriptor.ProductID),
	}

	serial := strings.TrimSpace(descriptor.Serial)
	if serial != "" {
		return strings.Join(append(parts, "serial", serial), "\x00")
	}

	attachment := append(
		parts,
		"path",
		string(descriptor.Transport),
		strings.TrimSpace(descriptor.Path),
	)
	if len(descriptor.ATR) != 0 {
		attachment = append(attachment, "atr", hex.EncodeToString(descriptor.ATR))
	}

	return strings.Join(attachment, "\x00")
}
