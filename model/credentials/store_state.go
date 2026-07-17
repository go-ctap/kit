package credentials

type StoreStateResult struct {
	AuthenticatorIdentifierHex string `json:"authenticatorIdentifierHex"`
	CredentialStoreStateHex    string `json:"credentialStoreStateHex"`
}
