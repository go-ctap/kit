package model

import "github.com/go-ctap/kit/model/largeblobs"

type LargeBlobReadOutput struct {
	Report largeblobs.ReadReport `json:"report"`
}

type LargeBlobListOutput struct {
	Report largeblobs.ListReport `json:"report"`
}

type LargeBlobMutationOutput struct {
	Preview largeblobs.MutationPreview `json:"preview"`
	Result  *largeblobs.MutationResult `json:"result"`
}
