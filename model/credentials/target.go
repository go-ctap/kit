package credentials

type CredentialTarget struct {
	Record CredentialRecord `json:"record"`
	RP     RelyingParty     `json:"rp"`
	User   UserIdentity     `json:"user"`
}

type RelyingParty struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	IDHashHex string `json:"idHashHex,omitempty"`
}

type UserIdentity struct {
	UserIDHex   string `json:"userIDHex,omitempty"`
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}
