package largeblobs

import "errors"

var (
	ErrUnsupportedLargeBlobs  = errors.New("ctapkit: unsupported large blobs")
	ErrConfirmationRequired   = errors.New("ctapkit: large blob mutation confirmation required")
	ErrLargeBlobKeyMissing    = errors.New("ctapkit: large blob key missing")
	ErrLargeBlobArrayTooBig   = errors.New("ctapkit: large blob array too large")
	ErrBlobNotFound           = errors.New("ctapkit: large blob not found")
	ErrLargeBlobStorageFull   = errors.New("ctapkit: large blob storage full")
	ErrLargeBlobInvalid       = errors.New("ctapkit: invalid large blob array")
	ErrLargeBlobWriteSequence = errors.New("ctapkit: invalid large blob write sequence")
	ErrLargeBlobIntegrity     = errors.New("ctapkit: large blob integrity failure")
)
