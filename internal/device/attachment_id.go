package device

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/go-ctap/kit/internal/discovery"
)

const attachmentIDLength = 16

// AttachmentID returns an opaque identifier for one transport endpoint.
func AttachmentID(descriptor discovery.Descriptor) string {
	parts := []string{
		"ctapkit-attachment-v1",
		string(descriptor.Transport),
		strings.TrimSpace(descriptor.Path),
	}
	seed := strings.Join(parts, "\x00")
	sum := sha256.Sum256([]byte(seed))

	return hex.EncodeToString(sum[:])[:attachmentIDLength]
}
