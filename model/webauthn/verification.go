package webauthn

import "github.com/telesma-app/ctap/attestation"

// VerificationStatus is the local integrity outcome of a WebAuthn operation result.
type VerificationStatus string

const (
	VerificationStatusVerified    VerificationStatus = "verified"
	VerificationStatusFailed      VerificationStatus = "failed"
	VerificationStatusUnavailable VerificationStatus = "unavailable"
)

// AttestationType describes the attestation evidence verified by ctapkit.
type AttestationType string

const (
	AttestationTypeNone        AttestationType = "none"
	AttestationTypeSelf        AttestationType = "self"
	AttestationTypeBasic       AttestationType = "basic"
	AttestationTypeUnsupported AttestationType = "unsupported"
)

// SignCountStatus describes a comparison with a caller-supplied previous signature counter.
type SignCountStatus string

const (
	SignCountStatusNotChecked  SignCountStatus = "not_checked"
	SignCountStatusUnsupported SignCountStatus = "unsupported"
	SignCountStatusAdvanced    SignCountStatus = "advanced"
	SignCountStatusNotAdvanced SignCountStatus = "not_advanced"
)

// VerificationIssueCode identifies a compact, stable reason for a verification outcome.
type VerificationIssueCode string

const (
	VerificationIssueResultMalformed                  VerificationIssueCode = "webauthn.verification.result_malformed"
	VerificationIssueResultMismatch                   VerificationIssueCode = "webauthn.verification.result_mismatch"
	VerificationIssueResultRPIDMismatch               VerificationIssueCode = "webauthn.verification.result_rp_id_mismatch"
	VerificationIssueAuthenticatorDataMalformed       VerificationIssueCode = "webauthn.verification.authenticator_data_malformed"
	VerificationIssueRPIDHashMismatch                 VerificationIssueCode = "webauthn.verification.rp_id_hash_mismatch"
	VerificationIssueUserPresenceMissing              VerificationIssueCode = "webauthn.verification.user_presence_missing"
	VerificationIssueUserVerificationMissing          VerificationIssueCode = "webauthn.verification.user_verification_missing"
	VerificationIssueAttestedCredentialDataMissing    VerificationIssueCode = "webauthn.verification.attested_credential_data_missing"
	VerificationIssueAttestedCredentialDataUnexpected VerificationIssueCode = "webauthn.verification.attested_credential_data_unexpected"
	VerificationIssueCredentialAlgorithmDisallowed    VerificationIssueCode = "webauthn.verification.credential_algorithm_disallowed"
	VerificationIssueCredentialAlgorithmUnsupported   VerificationIssueCode = "webauthn.verification.credential_algorithm_unsupported"
	VerificationIssueCredentialKeyMalformed           VerificationIssueCode = "webauthn.verification.credential_key_malformed"
	VerificationIssueCredentialDisallowed             VerificationIssueCode = "webauthn.verification.credential_disallowed"
	VerificationIssueAttestationObjectMalformed       VerificationIssueCode = "webauthn.verification.attestation_object_malformed"
	VerificationIssueAttestationObjectMismatch        VerificationIssueCode = "webauthn.verification.attestation_object_mismatch"
	VerificationIssueAttestationStatementMalformed    VerificationIssueCode = "webauthn.verification.attestation_statement_malformed"
	VerificationIssueAttestationFormatUnsupported     VerificationIssueCode = "webauthn.verification.attestation_format_unsupported"
	VerificationIssueAttestationSignatureInvalid      VerificationIssueCode = "webauthn.verification.attestation_signature_invalid"
	VerificationIssueAssertionMissing                 VerificationIssueCode = "webauthn.verification.assertion_missing"
	VerificationIssueAssertionCountUnexpected         VerificationIssueCode = "webauthn.verification.assertion_count_unexpected"
	VerificationIssueVerificationMaterialMissing      VerificationIssueCode = "webauthn.verification.verification_material_missing"
	VerificationIssueVerificationMaterialAmbiguous    VerificationIssueCode = "webauthn.verification.verification_material_ambiguous"
	VerificationIssueVerificationKeyMalformed         VerificationIssueCode = "webauthn.verification.verification_key_malformed"
	VerificationIssueSignatureMalformed               VerificationIssueCode = "webauthn.verification.signature_malformed"
	VerificationIssueAssertionSignatureInvalid        VerificationIssueCode = "webauthn.verification.assertion_signature_invalid"
	VerificationWarningSignCountNotAdvanced           VerificationIssueCode = "webauthn.verification.sign_count_not_advanced"
)

// CredentialVerificationMaterial supplies assertion verification state owned by the application.
type CredentialVerificationMaterial struct {
	CredentialIDHex   string  `json:"credentialIDHex"`
	PublicKeyCOSEHex  string  `json:"publicKeyCOSEHex"`
	PreviousSignCount *uint32 `json:"previousSignCount,omitempty"`
}

type MakeCredentialVerification struct {
	Status                         VerificationStatus                               `json:"status"`
	RPIDHashMatches                bool                                             `json:"rpIDHashMatches"`
	UserPresenceRequirementMet     bool                                             `json:"userPresenceRequirementMet"`
	UserVerificationRequirementMet bool                                             `json:"userVerificationRequirementMet"`
	CredentialAlgorithmAllowed     bool                                             `json:"credentialAlgorithmAllowed"`
	AttestationFormat              attestation.AttestationStatementFormatIdentifier `json:"attestationFormat"`
	AttestationType                AttestationType                                  `json:"attestationType"`
	SignatureValid                 *bool                                            `json:"signatureValid,omitempty"`
	Issues                         []VerificationIssueCode                          `json:"issues,omitempty"`
}

type AssertionVerification struct {
	Index                          uint                    `json:"index"`
	CredentialIDHex                string                  `json:"credentialIDHex"`
	Status                         VerificationStatus      `json:"status"`
	RPIDHashMatches                bool                    `json:"rpIDHashMatches"`
	UserPresenceRequirementMet     bool                    `json:"userPresenceRequirementMet"`
	UserVerificationRequirementMet bool                    `json:"userVerificationRequirementMet"`
	CredentialAllowed              bool                    `json:"credentialAllowed"`
	SignatureValid                 *bool                   `json:"signatureValid,omitempty"`
	SignCount                      SignCountStatus         `json:"signCount"`
	Issues                         []VerificationIssueCode `json:"issues,omitempty"`
	Warnings                       []VerificationIssueCode `json:"warnings,omitempty"`
}

type GetAssertionVerification struct {
	Status     VerificationStatus      `json:"status"`
	Assertions []AssertionVerification `json:"assertions"`
	Issues     []VerificationIssueCode `json:"issues,omitempty"`
}
