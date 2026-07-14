package device

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/go-ctap/kit/transport"
)

const fingerprintLength = 16

// Fingerprint returns an opaque identifier for one transport attachment.
// It is not stable across process sessions or device reinsertion.
func Fingerprint(mode transport.Mode, path string) string {
	seed := strings.Join([]string{
		"ctapkit-fingerprint-v1",
		string(mode),
		strings.TrimSpace(path),
	}, "\x00")
	sum := sha256.Sum256([]byte(seed))

	return hex.EncodeToString(sum[:])[:fingerprintLength]
}
