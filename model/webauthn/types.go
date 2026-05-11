package webauthn

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/model/safety"
	"github.com/samber/lo"
)

const PublicKeyCredentialTypePublicKey = "public-key"

type RelyingParty struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type User struct {
	IDHex       string `json:"userIDHex,omitempty"`
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

type CredentialDescriptor struct {
	Type       string   `json:"type,omitempty"`
	IDHex      string   `json:"credentialIDHex"`
	Transports []string `json:"transports,omitempty"`
}

type CredentialParameter struct {
	Type      string `json:"type,omitempty"`
	Algorithm int64  `json:"alg"`
}

type AuthenticatorOptions struct {
	ResidentKey      *bool `json:"residentKey,omitempty"`
	UserPresence     *bool `json:"userPresence,omitempty"`
	UserVerification *bool `json:"userVerification,omitempty"`
}

type MakeCredentialInput struct {
	RP               RelyingParty           `json:"rp"`
	User             User                   `json:"user"`
	ClientDataJSON   []byte                 `json:"clientDataJSON"`
	PubKeyCredParams []CredentialParameter  `json:"pubKeyCredParams"`
	ExcludeList      []CredentialDescriptor `json:"excludeList,omitempty"`
	Options          AuthenticatorOptions   `json:"options,omitempty"`
}

type GetAssertionInput struct {
	RPID           string                 `json:"rpID"`
	ClientDataJSON []byte                 `json:"clientDataJSON"`
	AllowList      []CredentialDescriptor `json:"allowList,omitempty"`
	Options        AuthenticatorOptions   `json:"options,omitempty"`
}

type MakeCredentialPreview struct {
	Device           report.DeviceReport    `json:"device"`
	RP               RelyingParty           `json:"rp"`
	User             User                   `json:"user"`
	PubKeyCredParams []CredentialParameter  `json:"pubKeyCredParams"`
	ExcludeList      []CredentialDescriptor `json:"excludeList,omitempty"`
	Options          AuthenticatorOptions   `json:"options,omitempty"`
	Warnings         []safety.Warning       `json:"warnings,omitempty"`
}

type MakeCredentialResult struct {
	DeviceID                 string `json:"deviceId"`
	RPID                     string `json:"rpID"`
	Format                   string `json:"fmt"`
	CredentialIDHex          string `json:"credentialIDHex"`
	PublicKeyCOSEHex         string `json:"publicKeyCOSEHex"`
	AuthenticatorDataHex     string `json:"authenticatorDataHex"`
	AttestationObjectCBORHex string `json:"attestationObjectCBORHex"`
	AAGUID                   string `json:"aaguid,omitempty"`
	SignCount                uint32 `json:"signCount"`
	UserPresent              bool   `json:"userPresent"`
	UserVerified             bool   `json:"userVerified"`
	EnterpriseAttestation    bool   `json:"enterpriseAttestation,omitempty"`
}

type GetAssertionResult struct {
	DeviceID   string      `json:"deviceId"`
	RPID       string      `json:"rpID"`
	Assertions []Assertion `json:"assertions,omitempty"`
}

type Assertion struct {
	Index                uint                 `json:"index"`
	Credential           CredentialDescriptor `json:"credential"`
	AuthenticatorDataHex string               `json:"authenticatorDataHex"`
	SignatureHex         string               `json:"signatureHex"`
	User                 *User                `json:"user,omitempty"`
	NumberOfCredentials  uint                 `json:"numberOfCredentials,omitempty"`
	UserSelected         bool                 `json:"userSelected,omitempty"`
	SignCount            uint32               `json:"signCount"`
	UserPresent          bool                 `json:"userPresent"`
	UserVerified         bool                 `json:"userVerified"`
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
	userIDHex, err := normalizeHex(input.User.IDHex, "user id")
	if err != nil {
		return MakeCredentialInput{}, err
	}
	if userIDHex == "" {
		return MakeCredentialInput{}, invalidInput("user id is required")
	}
	input.User.IDHex = userIDHex

	if len(input.ClientDataJSON) == 0 {
		return MakeCredentialInput{}, invalidInput("clientDataJSON is required")
	}
	input.ClientDataJSON = lo.Clone(input.ClientDataJSON)

	if len(input.PubKeyCredParams) == 0 {
		return MakeCredentialInput{}, invalidInput("public key credential parameters are required")
	}

	pubKeyCredParams, err := lo.MapErr(input.PubKeyCredParams, func(param CredentialParameter, _ int) (CredentialParameter, error) {
		param = normalizeCredentialParameter(param)
		if param.Algorithm == 0 {
			return CredentialParameter{}, invalidInput("public key credential algorithm is required")
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

func normalizeDescriptors(in []CredentialDescriptor) ([]CredentialDescriptor, error) {
	return lo.MapErr(in, func(descriptor CredentialDescriptor, _ int) (CredentialDescriptor, error) {
		descriptor.Type = credentialTypeOrDefault(descriptor.Type)
		idHex, err := normalizeHex(descriptor.IDHex, "credential id")
		if err != nil {
			return CredentialDescriptor{}, err
		}
		if idHex == "" {
			return CredentialDescriptor{}, invalidInput("credential id is required")
		}
		descriptor.IDHex = idHex

		return descriptor, nil
	})
}

func normalizeCredentialParameter(param CredentialParameter) CredentialParameter {
	param.Type = credentialTypeOrDefault(param.Type)

	return param
}

func credentialTypeOrDefault(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return PublicKeyCredentialTypePublicKey
	}

	return value
}

func normalizeHex(value string, label string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}

	decoded, err := hex.DecodeString(value)
	if err != nil {
		return "", invalidInput("%s must be valid hex: %q", label, value)
	}

	return hex.EncodeToString(decoded), nil
}

func invalidInput(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidInput}, args...)...)
}
