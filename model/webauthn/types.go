package webauthn

import (
	"fmt"
	"strings"

	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/model/safety"
	"github.com/samber/lo"
)

const PublicKeyCredentialTypePublicKey = credential.PublicKeyCredentialTypePublicKey

type AuthenticatorOptions struct {
	ResidentKey      *bool `json:"residentKey,omitempty"`
	UserPresence     *bool `json:"userPresence,omitempty"`
	UserVerification *bool `json:"userVerification,omitempty"`
}

type MakeCredentialInput struct {
	RP               credential.PublicKeyCredentialRpEntity     `json:"rp"`
	User             credential.PublicKeyCredentialUserEntity   `json:"user"`
	ClientDataJSON   []byte                                     `json:"clientDataJSON"`
	PubKeyCredParams []credential.PublicKeyCredentialParameters `json:"pubKeyCredParams"`
	ExcludeList      []credential.PublicKeyCredentialDescriptor `json:"excludeList,omitempty"`
	Options          AuthenticatorOptions                       `json:"options,omitempty"`
}

type GetAssertionInput struct {
	RPID           string                                     `json:"rpID"`
	ClientDataJSON []byte                                     `json:"clientDataJSON"`
	AllowList      []credential.PublicKeyCredentialDescriptor `json:"allowList,omitempty"`
	Options        AuthenticatorOptions                       `json:"options,omitempty"`
}

type MakeCredentialPreview struct {
	Device           report.DeviceReport                        `json:"device"`
	RP               credential.PublicKeyCredentialRpEntity     `json:"rp"`
	User             credential.PublicKeyCredentialUserEntity   `json:"user"`
	PubKeyCredParams []credential.PublicKeyCredentialParameters `json:"pubKeyCredParams"`
	ExcludeList      []credential.PublicKeyCredentialDescriptor `json:"excludeList,omitempty"`
	Options          AuthenticatorOptions                       `json:"options,omitempty"`
	Warnings         []safety.Warning                           `json:"warnings,omitempty"`
}

type MakeCredentialResult struct {
	DeviceID                 string                                           `json:"deviceId"`
	RPID                     string                                           `json:"rpID"`
	Format                   attestation.AttestationStatementFormatIdentifier `json:"fmt"`
	CredentialIDHex          string                                           `json:"credentialIDHex"`
	PublicKeyCOSEHex         string                                           `json:"publicKeyCOSEHex"`
	AuthenticatorDataHex     string                                           `json:"authenticatorDataHex"`
	AttestationObjectCBORHex string                                           `json:"attestationObjectCBORHex"`
	AAGUID                   string                                           `json:"aaguid,omitempty"`
	SignCount                uint32                                           `json:"signCount"`
	UserPresent              bool                                             `json:"userPresent"`
	UserVerified             bool                                             `json:"userVerified"`
	EnterpriseAttestation    bool                                             `json:"enterpriseAttestation,omitempty"`
}

type GetAssertionResult struct {
	DeviceID   string      `json:"deviceId"`
	RPID       string      `json:"rpID"`
	Assertions []Assertion `json:"assertions,omitempty"`
}

type Assertion struct {
	Index                uint                                      `json:"index"`
	Credential           credential.PublicKeyCredentialDescriptor  `json:"credential"`
	AuthenticatorDataHex string                                    `json:"authenticatorDataHex"`
	SignatureHex         string                                    `json:"signatureHex"`
	User                 *credential.PublicKeyCredentialUserEntity `json:"user,omitempty"`
	NumberOfCredentials  uint                                      `json:"numberOfCredentials,omitempty"`
	UserSelected         bool                                      `json:"userSelected,omitempty"`
	SignCount            uint32                                    `json:"signCount"`
	UserPresent          bool                                      `json:"userPresent"`
	UserVerified         bool                                      `json:"userVerified"`
}

func BuildMakeCredentialPreview(device report.DeviceReport, input MakeCredentialInput) (MakeCredentialPreview, error) {
	normalized, err := NormalizeMakeCredentialInput(input)
	if err != nil {
		return MakeCredentialPreview{}, err
	}

	return MakeCredentialPreview{
		Device:           device,
		RP:               normalized.RP,
		User:             normalized.User,
		PubKeyCredParams: normalized.PubKeyCredParams,
		ExcludeList:      normalized.ExcludeList,
		Options:          normalized.Options,
		Warnings: []safety.Warning{
			{
				Severity: safety.SeverityWarning,
				Code:     "webauthn.make_credential.mutation",
				Message:  "A new credential may be created on this authenticator.",
			},
		},
	}, nil
}

func NormalizeMakeCredentialInput(input MakeCredentialInput) (MakeCredentialInput, error) {
	input.RP.ID = strings.TrimSpace(input.RP.ID)
	input.RP.Name = strings.TrimSpace(input.RP.Name)
	if input.RP.ID == "" {
		return MakeCredentialInput{}, invalidInput("relying party id is required")
	}

	input.User.Name = strings.TrimSpace(input.User.Name)
	input.User.DisplayName = strings.TrimSpace(input.User.DisplayName)
	if len(input.User.ID) == 0 {
		return MakeCredentialInput{}, invalidInput("user id is required")
	}
	input.User.ID = lo.Clone(input.User.ID)

	if len(input.ClientDataJSON) == 0 {
		return MakeCredentialInput{}, invalidInput("clientDataJSON is required")
	}
	input.ClientDataJSON = lo.Clone(input.ClientDataJSON)

	if len(input.PubKeyCredParams) == 0 {
		return MakeCredentialInput{}, invalidInput("public key credential parameters are required")
	}

	pubKeyCredParams, err := lo.MapErr(input.PubKeyCredParams, func(param credential.PublicKeyCredentialParameters, _ int) (credential.PublicKeyCredentialParameters, error) {
		param = normalizeCredentialParameter(param)
		if param.Algorithm == 0 {
			return credential.PublicKeyCredentialParameters{}, invalidInput("public key credential algorithm is required")
		}

		return param, nil
	})
	if err != nil {
		return MakeCredentialInput{}, err
	}
	input.PubKeyCredParams = pubKeyCredParams

	excludeList, err := normalizeDescriptors(input.ExcludeList)
	if err != nil {
		return MakeCredentialInput{}, err
	}
	input.ExcludeList = excludeList

	return input, nil
}

func NormalizeGetAssertionInput(input GetAssertionInput) (GetAssertionInput, error) {
	input.RPID = strings.TrimSpace(input.RPID)
	if input.RPID == "" {
		return GetAssertionInput{}, invalidInput("relying party id is required")
	}

	if len(input.ClientDataJSON) == 0 {
		return GetAssertionInput{}, invalidInput("clientDataJSON is required")
	}
	input.ClientDataJSON = lo.Clone(input.ClientDataJSON)

	allowList, err := normalizeDescriptors(input.AllowList)
	if err != nil {
		return GetAssertionInput{}, err
	}
	input.AllowList = allowList

	return input, nil
}

func normalizeDescriptors(in []credential.PublicKeyCredentialDescriptor) ([]credential.PublicKeyCredentialDescriptor, error) {
	return lo.MapErr(in, func(descriptor credential.PublicKeyCredentialDescriptor, _ int) (credential.PublicKeyCredentialDescriptor, error) {
		descriptor.Type = credentialTypeOrDefault(descriptor.Type)
		if len(descriptor.ID) == 0 {
			return credential.PublicKeyCredentialDescriptor{}, invalidInput("credential id is required")
		}
		descriptor.ID = lo.Clone(descriptor.ID)
		descriptor.Transports = lo.Clone(descriptor.Transports)

		return descriptor, nil
	})
}

func normalizeCredentialParameter(param credential.PublicKeyCredentialParameters) credential.PublicKeyCredentialParameters {
	param.Type = credentialTypeOrDefault(param.Type)

	return param
}

func credentialTypeOrDefault(value credential.PublicKeyCredentialType) credential.PublicKeyCredentialType {
	trimmed := strings.TrimSpace(string(value))
	if trimmed == "" {
		return PublicKeyCredentialTypePublicKey
	}

	return credential.PublicKeyCredentialType(trimmed)
}

func invalidInput(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidInput}, args...)...)
}
