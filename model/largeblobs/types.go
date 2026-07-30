package largeblobs

import "github.com/go-ctap/kit/model/credentials"

type LargeBlobKeyState string

const (
	LargeBlobKeyAvailable LargeBlobKeyState = "available"
	LargeBlobKeyMissing   LargeBlobKeyState = "missing"
)

type ReadState string

const (
	// ReadStateMissing means no largeBlobKey was returned for the credential or
	// no conforming array entry authenticated with its key.
	ReadStateMissing ReadState = "missing"

	// ReadStatePresent means RawBytes contains the opaque, decompressed
	// per-credential data.
	ReadStatePresent ReadState = "present"
)

type EntryState string

const (
	// EntryStateMatched means AEAD authentication and payload decompression
	// succeeded with an enumerated credential key.
	EntryStateMatched EntryState = "matched"

	// EntryStateOrphaned means the conforming entry did not authenticate with
	// any valid key returned while enumerating discoverable credentials.
	EntryStateOrphaned EntryState = "orphaned"

	// EntryStateNonconforming means the entry violates a required large-blob
	// map restriction represented by protocol.LargeBlob.
	EntryStateNonconforming EntryState = "nonconforming"

	// EntryStateCorrupt means AEAD authentication succeeded, but DEFLATE or
	// origSize validation failed. CTAP garbage collection retains this entry.
	EntryStateCorrupt EntryState = "corrupt"
)

type SupportReport struct {
	LargeBlobs                  bool `json:"largeBlobs"`
	LargeBlobKeyExtension       bool `json:"largeBlobKeyExtension"`
	MaxSerializedLargeBlobArray uint `json:"maxSerializedLargeBlobArray,omitempty"`
}

type BlobTarget struct {
	CredentialIDHex string                   `json:"credentialIDHex"`
	RP              credentials.RelyingParty `json:"rp"`
	User            credentials.UserIdentity `json:"user"`
}
