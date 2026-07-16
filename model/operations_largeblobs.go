package model

import "github.com/go-ctap/kit/model/largeblobs"

type ReadLargeBlobOperation struct {
	CredentialIDHex string                `json:"credentialIdHex"`
	DecodeMode      largeblobs.DecodeMode `json:"decodeMode,omitempty"`
}

func (ReadLargeBlobOperation) Kind() OperationKind { return OperationReadLargeBlob }
func (ReadLargeBlobOperation) IsDryRun() bool      { return false }
func (ReadLargeBlobOperation) ctapkitOperation()   {}

type ListLargeBlobsOperation struct {
	Refresh bool `json:"refresh,omitempty"`
}

func (ListLargeBlobsOperation) Kind() OperationKind { return OperationListLargeBlobs }
func (ListLargeBlobsOperation) IsDryRun() bool      { return false }
func (ListLargeBlobsOperation) ctapkitOperation()   {}

type WriteLargeBlobOperation struct {
	CredentialIDHex string `json:"credentialIdHex"`
	Payload         []byte `json:"payload,omitempty"`
	// PrepareInventoryRefresh requests a grant that can serve the next inventory refresh.
	PrepareInventoryRefresh bool   `json:"prepareInventoryRefresh,omitempty"`
	Confirmed               bool   `json:"confirmed,omitempty"`
	ConfirmationMessage     string `json:"confirmationMessage,omitempty"`
	DryRun                  bool   `json:"dryRun,omitempty"`
}

func (WriteLargeBlobOperation) Kind() OperationKind { return OperationWriteLargeBlob }
func (op WriteLargeBlobOperation) IsDryRun() bool   { return op.DryRun }
func (WriteLargeBlobOperation) ctapkitOperation()   {}

type DeleteLargeBlobOperation struct {
	CredentialIDHex string `json:"credentialIdHex"`
	// PrepareInventoryRefresh requests a grant that can serve the next inventory refresh.
	PrepareInventoryRefresh bool   `json:"prepareInventoryRefresh,omitempty"`
	Confirmed               bool   `json:"confirmed,omitempty"`
	ConfirmationMessage     string `json:"confirmationMessage,omitempty"`
	DryRun                  bool   `json:"dryRun,omitempty"`
}

func (DeleteLargeBlobOperation) Kind() OperationKind { return OperationDeleteLargeBlob }
func (op DeleteLargeBlobOperation) IsDryRun() bool   { return op.DryRun }
func (DeleteLargeBlobOperation) ctapkitOperation()   {}

type GarbageCollectLargeBlobsOperation struct {
	// PrepareInventoryRefresh requests a grant that can serve the next inventory refresh.
	PrepareInventoryRefresh bool   `json:"prepareInventoryRefresh,omitempty"`
	Confirmed               bool   `json:"confirmed,omitempty"`
	ConfirmationMessage     string `json:"confirmationMessage,omitempty"`
	DryRun                  bool   `json:"dryRun,omitempty"`
}

func (GarbageCollectLargeBlobsOperation) Kind() OperationKind {
	return OperationGarbageCollectLargeBlobs
}
func (op GarbageCollectLargeBlobsOperation) IsDryRun() bool { return op.DryRun }
func (GarbageCollectLargeBlobsOperation) ctapkitOperation() {}
