package device

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"
)

const deviceIDLength = 6

var deviceIDEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func ID(vendorID uint16, productID uint16, serial string, path string) string {
	return Key(vendorID, productID, serial, path)[:deviceIDLength]
}

func Key(vendorID uint16, productID uint16, serial string, path string) string {
	seed, _ := deviceSeed(vendorID, productID, serial, path)
	sum := sha256.Sum256([]byte(seed))

	return strings.ToLower(deviceIDEncoding.EncodeToString(sum[:]))
}

func Stable(vendorID uint16, productID uint16, serial string, path string) bool {
	_, stable := deviceSeed(vendorID, productID, serial, path)

	return stable
}

func deviceSeed(vendorID uint16, productID uint16, serialValue string, path string) (string, bool) {
	parts := []string{
		fmt.Sprintf("%04x", vendorID),
		fmt.Sprintf("%04x", productID),
	}

	serialValue = strings.TrimSpace(serialValue)
	if serialValue != "" {
		return strings.Join(append(parts, serialValue), "|"), true
	}

	return strings.Join(append(parts, strings.TrimSpace(path)), "|"), false
}
