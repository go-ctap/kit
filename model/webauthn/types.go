package webauthn

import (
	"slices"
	"strings"

	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/protocol"
	ctapwebauthn "github.com/go-ctap/ctap/webauthn"
	"github.com/go-ctap/kit/model/failure"
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
	RP               credential.PublicKeyCredentialRpEntity                   `json:"rp"`
	User             credential.PublicKeyCredentialUserEntity                 `json:"user"`
	ClientDataJSON   []byte                                                   `json:"clientDataJSON"`
	PubKeyCredParams []credential.PublicKeyCredentialParameters               `json:"pubKeyCredParams"`
	ExcludeList      []credential.PublicKeyCredentialDescriptor               `json:"excludeList,omitempty"`
	Options          AuthenticatorOptions                                     `json:"options,omitempty"`
	Extensions       *ctapwebauthn.CreateAuthenticationExtensionsClientInputs `json:"extensions,omitempty"`
}

type GetAssertionInput struct {
	RPID           string                                                `json:"rpID"`
	ClientDataJSON []byte                                                `json:"clientDataJSON"`
	AllowList      []credential.PublicKeyCredentialDescriptor            `json:"allowList,omitempty"`
	Options        AuthenticatorOptions                                  `json:"options,omitempty"`
	Extensions     *ctapwebauthn.GetAuthenticationExtensionsClientInputs `json:"extensions,omitempty"`
}

type MakeCredentialPreview struct {
	Device   report.DeviceReport `json:"device"`
	Input    MakeCredentialInput `json:"input"`
	Warnings []safety.Warning    `json:"warnings,omitempty"`
}

type GetAssertionPreview struct {
	Device   report.DeviceReport `json:"device"`
	Input    GetAssertionInput   `json:"input"`
	Warnings []safety.Warning    `json:"warnings,omitempty"`
}

type MakeCredentialResult struct {
	DeviceFingerprint        string                                           `json:"deviceFingerprint"`
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
	ExtensionResults         *MakeCredentialExtensionResults                  `json:"extensionResults,omitempty"`
}

type GetAssertionResult struct {
	DeviceFingerprint string      `json:"deviceFingerprint"`
	RPID              string      `json:"rpID"`
	Assertions        []Assertion `json:"assertions,omitempty"`
}

type Assertion struct {
	Index                uint                                      `json:"index"`
	Credential           credential.PublicKeyCredentialDescriptor  `json:"credential"`
	AuthenticatorDataHex string                                    `json:"authenticatorDataHex"`
	SignatureHex         string                                    `json:"signatureHex"`
	User                 *credential.PublicKeyCredentialUserEntity `json:"user,omitempty"`
	NumberOfCredentials  *uint                                     `json:"numberOfCredentials,omitempty"`
	UserSelected         *bool                                     `json:"userSelected,omitempty"`
	SignCount            uint32                                    `json:"signCount"`
	UserPresent          bool                                      `json:"userPresent"`
	UserVerified         bool                                      `json:"userVerified"`
	ExtensionResults     *GetAssertionExtensionResults             `json:"extensionResults,omitempty"`
}

func BuildMakeCredentialPreview(
	device report.DeviceReport,
	info protocol.AuthenticatorGetInfoResponse,
	input MakeCredentialInput,
) (MakeCredentialPreview, error) {
	normalized, err := NormalizeMakeCredentialInput(input)
	if err != nil {
		return MakeCredentialPreview{}, err
	}
	if err := validateMakeCredentialCapabilities(info, normalized.Extensions); err != nil {
		return MakeCredentialPreview{}, err
	}

	return MakeCredentialPreview{
		Device: device,
		Input:  normalized,
		Warnings: slices.Concat([]safety.Warning{
			{
				Severity: safety.SeverityWarning,
				Code:     "webauthn.make_credential.mutation",
				Message:  "A new credential may be created on this authenticator.",
			},
		}, makeCredentialExtensionWarnings(info, normalized.Extensions)),
	}, nil
}

func BuildGetAssertionPreview(
	device report.DeviceReport,
	info protocol.AuthenticatorGetInfoResponse,
	input GetAssertionInput,
) (GetAssertionPreview, error) {
	normalized, err := NormalizeGetAssertionInput(input)
	if err != nil {
		return GetAssertionPreview{}, err
	}

	return GetAssertionPreview{
		Device:   device,
		Input:    normalized,
		Warnings: getAssertionExtensionWarnings(info, normalized.Extensions),
	}, nil
}

func NormalizeMakeCredentialInput(input MakeCredentialInput) (MakeCredentialInput, error) {
	input.RP.ID = strings.TrimSpace(input.RP.ID)
	input.RP.Name = strings.TrimSpace(input.RP.Name)
	if input.RP.ID == "" {
		return MakeCredentialInput{}, failure.New(failure.CodeRelyingPartyIDRequired, failure.WithPhase(failure.PhaseValidation))
	}

	input.User.Name = strings.TrimSpace(input.User.Name)
	input.User.DisplayName = strings.TrimSpace(input.User.DisplayName)
	if len(input.User.ID) == 0 {
		return MakeCredentialInput{}, failure.New(failure.CodeUserIDRequired, failure.WithPhase(failure.PhaseValidation))
	}
	input.User.ID = lo.Clone(input.User.ID)

	if len(input.ClientDataJSON) == 0 {
		return MakeCredentialInput{}, failure.New(failure.CodeClientDataJSONRequired, failure.WithPhase(failure.PhaseValidation))
	}
	input.ClientDataJSON = lo.Clone(input.ClientDataJSON)

	if len(input.PubKeyCredParams) == 0 {
		return MakeCredentialInput{}, failure.New(failure.CodePublicKeyCredentialParametersRequired, failure.WithPhase(failure.PhaseValidation))
	}

	pubKeyCredParams, err := lo.MapErr(input.PubKeyCredParams, func(param credential.PublicKeyCredentialParameters, _ int) (credential.PublicKeyCredentialParameters, error) {
		param = normalizeCredentialParameter(param)
		if param.Algorithm == 0 {
			return credential.PublicKeyCredentialParameters{}, failure.New(failure.CodePublicKeyCredentialAlgorithmRequired, failure.WithPhase(failure.PhaseValidation))
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
	input.Extensions, err = normalizeMakeCredentialExtensions(input.Extensions)
	if err != nil {
		return MakeCredentialInput{}, err
	}

	return input, nil
}

func NormalizeGetAssertionInput(input GetAssertionInput) (GetAssertionInput, error) {
	input.RPID = strings.TrimSpace(input.RPID)
	if input.RPID == "" {
		return GetAssertionInput{}, failure.New(failure.CodeRelyingPartyIDRequired, failure.WithPhase(failure.PhaseValidation))
	}

	if len(input.ClientDataJSON) == 0 {
		return GetAssertionInput{}, failure.New(failure.CodeClientDataJSONRequired, failure.WithPhase(failure.PhaseValidation))
	}
	input.ClientDataJSON = lo.Clone(input.ClientDataJSON)

	allowList, err := normalizeDescriptors(input.AllowList)
	if err != nil {
		return GetAssertionInput{}, err
	}
	input.AllowList = allowList
	input.Extensions, err = normalizeGetAssertionExtensions(input.Extensions, allowList)
	if err != nil {
		return GetAssertionInput{}, err
	}

	return input, nil
}

func normalizeDescriptors(in []credential.PublicKeyCredentialDescriptor) ([]credential.PublicKeyCredentialDescriptor, error) {
	return lo.MapErr(in, func(descriptor credential.PublicKeyCredentialDescriptor, _ int) (credential.PublicKeyCredentialDescriptor, error) {
		descriptor.Type = credentialTypeOrDefault(descriptor.Type)
		if len(descriptor.ID) == 0 {
			return credential.PublicKeyCredentialDescriptor{}, failure.New(failure.CodeCredentialIDRequired, failure.WithPhase(failure.PhaseValidation))
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
