package largeblobs

type ReadOperation struct {
	CredentialIDHex string `json:"credentialIDHex"`
}

type WriteOperation struct {
	CredentialIDHex string `json:"credentialIDHex"`
	Payload         []byte `json:"payload,omitempty"`
	DryRun          bool   `json:"dryRun,omitempty"`
}

type DeleteOperation struct {
	CredentialIDHex string `json:"credentialIDHex"`
	DryRun          bool   `json:"dryRun,omitempty"`
}

type GarbageCollectOperation struct {
	DryRun bool `json:"dryRun,omitempty"`
}
