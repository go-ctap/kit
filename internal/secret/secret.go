package secret

import (
	"encoding/json"
	"errors"
	"slices"
	"sync"
)

const secretRedacted = "[secret redacted]"

var ErrInvalidated = errors.New("ctapkit: secret invalidated")

type Handle struct {
	mu      sync.Mutex
	data    []byte
	invalid bool
}

func New(data []byte) *Handle {
	owned := slices.Clone(data)
	Zero(data)

	return &Handle{data: owned}
}

func (h *Handle) Bytes() ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.invalid {
		return nil, ErrInvalidated
	}

	return slices.Clone(h.data), nil
}

func (h *Handle) Invalidate() {
	h.mu.Lock()
	defer h.mu.Unlock()

	Zero(h.data)
	h.invalid = true
}

func (h *Handle) String() string {
	return secretRedacted
}

func (h *Handle) GoString() string {
	return secretRedacted
}

func (h *Handle) MarshalJSON() ([]byte, error) {
	return json.Marshal(secretRedacted)
}

func Zero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
