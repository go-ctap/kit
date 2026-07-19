package largeblobs

type MutationOutput struct {
	Preview MutationPreview `json:"preview"`
	Result  *MutationResult `json:"result"`
}
