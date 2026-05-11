package largeblobs

import (
	"github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/report"
)

type InspectionReport struct {
	Device            report.DeviceReport `json:"device"`
	Support           SupportReport       `json:"support"`
	Target            BlobTarget          `json:"target"`
	LargeBlobKeyState LargeBlobKeyState   `json:"largeBlobKeyState"`
	Array             ArrayState          `json:"array"`
}

type ReadReport struct {
	Device            report.DeviceReport `json:"device"`
	Support           SupportReport       `json:"support"`
	Target            BlobTarget          `json:"target"`
	LargeBlobKeyState LargeBlobKeyState   `json:"largeBlobKeyState"`
	Array             ArrayState          `json:"array"`
	BlobPresent       bool                `json:"blobPresent"`
	RawHex            string              `json:"rawHex,omitempty"`
	RawByteCount      int                 `json:"rawByteCount"`
	Decode            DecodeStatus        `json:"decode"`
	RawBytes          []byte              `json:"-"`
}

type ListReport struct {
	Device      report.DeviceReport `json:"device"`
	Support     SupportReport       `json:"support"`
	Array       ListArraySummary    `json:"array"`
	Credentials []ListCredential    `json:"credentials,omitempty"`
}

type ListArraySummary struct {
	Read               bool `json:"read"`
	BlobCount          int  `json:"blobCount"`
	MatchedBlobCount   int  `json:"matchedBlobCount"`
	UnmatchedBlobCount int  `json:"unmatchedBlobCount"`
}

type ListCredential struct {
	DeviceID          string                   `json:"deviceId,omitempty"`
	CredentialIDHex   string                   `json:"credentialIDHex"`
	RP                credentials.RelyingParty `json:"rp"`
	User              credentials.UserIdentity `json:"user"`
	LargeBlobKeyState LargeBlobKeyState        `json:"largeBlobKeyState"`
	BlobPresent       bool                     `json:"blobPresent"`
	BlobState         BlobState                `json:"blobState"`
	BlobByteCount     int                      `json:"blobByteCount"`
}

type ReadRequest struct {
	CredentialIDHex string     `json:"-"`
	DecodeMode      DecodeMode `json:"-"`
}

type ListRequest struct{}
