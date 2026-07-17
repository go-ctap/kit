package largeblobs

import "github.com/go-ctap/kit/model/credentials"

type LargeBlobKeyState string

const (
	LargeBlobKeyAvailable LargeBlobKeyState = "available"
	LargeBlobKeyMissing   LargeBlobKeyState = "missing"
)

type BlobState string

const (
	BlobStateUnknownKeyMissing BlobState = "unknown_key_missing"
	BlobStateMissing           BlobState = "missing"
	BlobStatePresent           BlobState = "present"
	BlobStateUnsupported       BlobState = "unsupported"
)

type SupportReport struct {
	LargeBlobs                  bool `json:"largeBlobs"`
	LargeBlobKeyExtension       bool `json:"largeBlobKeyExtension"`
	MaxSerializedLargeBlobArray uint `json:"maxSerializedLargeBlobArray,omitempty"`
}

type ArrayState struct {
	Read        bool      `json:"read"`
	BlobCount   int       `json:"blobCount"`
	BlobPresent bool      `json:"blobPresent"`
	BlobState   BlobState `json:"blobState"`
	BlobSize    int       `json:"blobSize,omitempty"`
}

type BlobTarget struct {
	CredentialIDHex string                   `json:"credentialIDHex"`
	RP              credentials.RelyingParty `json:"rp"`
	User            credentials.UserIdentity `json:"user"`
}
