package largeblobs

import (
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/model/safety"
)

type MutationOperation string

const (
	MutationCreate  MutationOperation = "create"
	MutationReplace MutationOperation = "replace"
	MutationDelete  MutationOperation = "delete"
	MutationNoBlob  MutationOperation = "no_blob"
	MutationGC      MutationOperation = "garbage_collect"
)

type MutationPreview struct {
	Operation                          MutationOperation   `json:"operation"`
	Device                             report.DeviceReport `json:"device"`
	Support                            SupportReport       `json:"support"`
	Target                             BlobTarget          `json:"target"`
	LargeBlobKeyState                  LargeBlobKeyState   `json:"largeBlobKeyState"`
	CurrentByteCount                   int                 `json:"currentByteCount"`
	ProposedByteCount                  int                 `json:"proposedByteCount"`
	SerializedLargeBlobArraySizeBefore int                 `json:"serializedLargeBlobArraySizeBefore"`
	SerializedLargeBlobArraySizeAfter  int                 `json:"serializedLargeBlobArraySizeAfter"`
	SerializedLargeBlobArrayLimit      *uint               `json:"serializedLargeBlobArrayLimit,omitempty"`
	BlobCountBefore                    int                 `json:"blobCountBefore"`
	BlobCountAfter                     int                 `json:"blobCountAfter"`
	MatchedBlobCount                   int                 `json:"matchedBlobCount,omitempty"`
	UnmatchedBlobCount                 int                 `json:"unmatchedBlobCount,omitempty"`
	DeletedBlobCount                   int                 `json:"deletedBlobCount,omitempty"`
	NoBlob                             bool                `json:"noBlob"`
	Noop                               bool                `json:"noop,omitempty"`
	Warnings                           []safety.Warning    `json:"warnings,omitempty"`
}

type MutationResult struct {
	Operation                          MutationOperation `json:"operation"`
	DeviceFingerprint                  string            `json:"deviceFingerprint"`
	CredentialIDHex                    string            `json:"credentialIDHex"`
	RPID                               string            `json:"rpID"`
	RPName                             string            `json:"rpName,omitempty"`
	UserIDHex                          string            `json:"userIDHex,omitempty"`
	UserName                           string            `json:"userName,omitempty"`
	DisplayName                        string            `json:"displayName,omitempty"`
	CurrentByteCount                   int               `json:"currentByteCount"`
	ProposedByteCount                  int               `json:"proposedByteCount"`
	SerializedLargeBlobArraySizeBefore int               `json:"serializedLargeBlobArraySizeBefore"`
	SerializedLargeBlobArraySizeAfter  int               `json:"serializedLargeBlobArraySizeAfter"`
	SerializedLargeBlobArrayLimit      *uint             `json:"serializedLargeBlobArrayLimit,omitempty"`
	BlobCountBefore                    int               `json:"blobCountBefore"`
	BlobCountAfter                     int               `json:"blobCountAfter"`
	MatchedBlobCount                   int               `json:"matchedBlobCount,omitempty"`
	UnmatchedBlobCount                 int               `json:"unmatchedBlobCount,omitempty"`
	DeletedBlobCount                   int               `json:"deletedBlobCount,omitempty"`
	NoBlob                             bool              `json:"noBlob"`
	Noop                               bool              `json:"noop,omitempty"`
}
