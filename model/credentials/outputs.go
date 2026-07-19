package credentials

type DeleteOutput struct {
	Preview DeletePreview `json:"preview"`
	Result  *DeleteResult `json:"result"`
}

type UpdateUserOutput struct {
	Preview UpdateUserPreview `json:"preview"`
	Result  *UpdateUserResult `json:"result"`
}
