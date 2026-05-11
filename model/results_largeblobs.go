package model

import "github.com/go-ctap/kit/model/largeblobs"

type LargeBlobReadOutput struct {
	Report largeblobs.ReadReport `json:"report"`
}

func (LargeBlobReadOutput) ctapkitResult() {}

type LargeBlobListOutput struct {
	Report largeblobs.ListReport `json:"report"`
}

func (LargeBlobListOutput) ctapkitResult() {}

type LargeBlobMutationOutput struct {
	Preview largeblobs.MutationPreview `json:"preview"`
	Result  *largeblobs.MutationResult `json:"result"`
}

func (LargeBlobMutationOutput) ctapkitResult() {}
