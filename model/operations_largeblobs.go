package model

import "github.com/go-ctap/kit/model/largeblobs"

type ReadLargeBlobOperation struct {
	CredentialIDHex string                `json:"credentialIdHex"`
	DecodeMode      largeblobs.DecodeMode `json:"decodeMode,omitempty"`
}

type WriteLargeBlobOperation struct {
	CredentialIDHex string `json:"credentialIdHex"`
	Payload         []byte `json:"payload,omitempty"`
	DryRun          bool   `json:"dryRun,omitempty"`
}

type DeleteLargeBlobOperation struct {
	CredentialIDHex string `json:"credentialIdHex"`
	DryRun          bool   `json:"dryRun,omitempty"`
}

type GarbageCollectLargeBlobsOperation struct {
	DryRun bool `json:"dryRun,omitempty"`
}
