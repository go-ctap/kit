package service

import (
	"context"
	"encoding/json"

	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/largeblobs"
	"github.com/go-ctap/kit/model/webauthn"
)

type OperationRequest struct {
	SessionID        SessionID              `json:"sessionId"`
	VerificationFlow model.VerificationFlow `json:"verificationFlow,omitempty"`
}

type CredentialDeleteRequest struct {
	OperationRequest
	CredentialIDHex     string `json:"credentialIdHex"`
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

type CredentialUpdateRequest struct {
	OperationRequest
	CredentialIDHex     string `json:"credentialIdHex"`
	UserIDHex           string `json:"userIdHex,omitempty"`
	Name                string `json:"name,omitempty"`
	DisplayName         string `json:"displayName,omitempty"`
	UserIDProvided      bool   `json:"userIdProvided,omitempty"`
	NameProvided        bool   `json:"nameProvided,omitempty"`
	DisplayProvided     bool   `json:"displayProvided,omitempty"`
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

type LargeBlobReadRequest struct {
	OperationRequest
	CredentialIDHex string                `json:"credentialIdHex"`
	DecodeMode      largeblobs.DecodeMode `json:"decodeMode,omitempty"`
}

type LargeBlobMutationRequest struct {
	OperationRequest
	CredentialIDHex     string `json:"credentialIdHex"`
	Payload             []byte `json:"payload,omitempty"`
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

type LargeBlobGarbageCollectRequest struct {
	OperationRequest
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

type PINSetRequest struct {
	OperationRequest
	// NewPIN is accepted from JSON for UI/service input, but MarshalJSON omits
	// it so request values cannot accidentally expose PINs in logs or events.
	NewPIN              string `json:"newPIN"`
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

type PINChangeRequest struct {
	OperationRequest
	// CurrentPIN and NewPIN are accepted from JSON for UI/service input, but
	// MarshalJSON omits them so request values cannot accidentally expose PINs.
	CurrentPIN          string `json:"currentPIN"`
	NewPIN              string `json:"newPIN"`
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

type AlwaysUVRequest struct {
	OperationRequest
	Target              config.AlwaysUVTarget `json:"target"`
	Confirmed           bool                  `json:"confirmed,omitempty"`
	ConfirmationMessage string                `json:"confirmationMessage,omitempty"`
	DryRun              bool                  `json:"dryRun,omitempty"`
}

type MinPINLengthRequest struct {
	OperationRequest
	NewMinPINLength     uint     `json:"newMinPINLength"`
	MinPinLengthRPIDs   []string `json:"minPinLengthRPIDs,omitempty"`
	ForceChangePin      bool     `json:"forceChangePin,omitempty"`
	PinComplexityPolicy bool     `json:"pinComplexityPolicy,omitempty"`
	Confirmed           bool     `json:"confirmed,omitempty"`
	ConfirmationMessage string   `json:"confirmationMessage,omitempty"`
	DryRun              bool     `json:"dryRun,omitempty"`
}

type BioEnrollRequest struct {
	OperationRequest
	TimeoutMilliseconds uint   `json:"timeoutMilliseconds,omitempty"`
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

type BioRenameRequest struct {
	OperationRequest
	TemplateIDHex       string `json:"templateIdHex"`
	FriendlyName        string `json:"friendlyName"`
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

type BioRemoveRequest struct {
	OperationRequest
	TemplateIDHex       string `json:"templateIdHex"`
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

type ResetFactoryRequest struct {
	OperationRequest
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

type MakeCredentialRequest struct {
	OperationRequest
	webauthn.MakeCredentialInput
	Confirmed           bool   `json:"confirmed,omitempty"`
	ConfirmationMessage string `json:"confirmationMessage,omitempty"`
	DryRun              bool   `json:"dryRun,omitempty"`
}

type GetAssertionRequest struct {
	OperationRequest
	webauthn.GetAssertionInput
}

func (s *Service) Inspect(ctx context.Context, req OperationRequest) (InspectEnvelope, error) {
	meta, result, err := runTypedOperation[model.InspectOutput](s, ctx, req, model.InspectOperation{})
	return InspectEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) ListCredentials(ctx context.Context, req OperationRequest) (CredentialsEnvelope, error) {
	meta, result, err := runTypedOperation[model.CredentialsOutput](s, ctx, req, model.ListCredentialsOperation{})
	return CredentialsEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) DeleteCredential(ctx context.Context, req CredentialDeleteRequest) (CredentialDeleteEnvelope, error) {
	meta, result, err := runTypedOperation[model.CredentialDeleteOutput](s, ctx, req.OperationRequest, model.DeleteCredentialOperation{
		CredentialIDHex:     req.CredentialIDHex,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
	return CredentialDeleteEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) UpdateCredentialUser(ctx context.Context, req CredentialUpdateRequest) (CredentialUpdateEnvelope, error) {
	meta, result, err := runTypedOperation[model.CredentialUpdateOutput](s, ctx, req.OperationRequest, model.UpdateCredentialUserOperation{
		CredentialIDHex:     req.CredentialIDHex,
		UserIDHex:           req.UserIDHex,
		Name:                req.Name,
		DisplayName:         req.DisplayName,
		UserIDProvided:      req.UserIDProvided,
		NameProvided:        req.NameProvided,
		DisplayProvided:     req.DisplayProvided,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
	return CredentialUpdateEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) ReadLargeBlob(ctx context.Context, req LargeBlobReadRequest) (LargeBlobReadEnvelope, error) {
	meta, result, err := runTypedOperation[model.LargeBlobReadOutput](s, ctx, req.OperationRequest, model.ReadLargeBlobOperation{
		CredentialIDHex: req.CredentialIDHex,
		DecodeMode:      req.DecodeMode,
	})
	return LargeBlobReadEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) ListLargeBlobs(ctx context.Context, req OperationRequest) (LargeBlobListEnvelope, error) {
	meta, result, err := runTypedOperation[model.LargeBlobListOutput](s, ctx, req, model.ListLargeBlobsOperation{})
	return LargeBlobListEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) WriteLargeBlob(ctx context.Context, req LargeBlobMutationRequest) (LargeBlobMutationEnvelope, error) {
	meta, result, err := runTypedOperation[model.LargeBlobMutationOutput](s, ctx, req.OperationRequest, model.WriteLargeBlobOperation{
		CredentialIDHex:     req.CredentialIDHex,
		Payload:             req.Payload,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
	return LargeBlobMutationEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) DeleteLargeBlob(ctx context.Context, req LargeBlobMutationRequest) (LargeBlobMutationEnvelope, error) {
	meta, result, err := runTypedOperation[model.LargeBlobMutationOutput](s, ctx, req.OperationRequest, model.DeleteLargeBlobOperation{
		CredentialIDHex:     req.CredentialIDHex,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
	return LargeBlobMutationEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) GarbageCollectLargeBlobs(ctx context.Context, req LargeBlobGarbageCollectRequest) (LargeBlobMutationEnvelope, error) {
	meta, result, err := runTypedOperation[model.LargeBlobMutationOutput](s, ctx, req.OperationRequest, model.GarbageCollectLargeBlobsOperation{
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
	return LargeBlobMutationEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) ConfigStatus(ctx context.Context, req OperationRequest) (ConfigStatusEnvelope, error) {
	meta, result, err := runTypedOperation[model.ConfigStatusOutput](s, ctx, req, model.ConfigStatusOperation{})
	return ConfigStatusEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) SetPIN(ctx context.Context, req PINSetRequest) (PINEnvelope, error) {
	meta, result, err := runTypedOperation[model.PINOutput](s, ctx, req.OperationRequest, model.SetPINOperation{
		NewPIN:              req.NewPIN,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
	return PINEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (req PINSetRequest) MarshalJSON() ([]byte, error) {
	type pinSetRequest struct {
		OperationRequest
		Confirmed           bool   `json:"confirmed,omitempty"`
		ConfirmationMessage string `json:"confirmationMessage,omitempty"`
		DryRun              bool   `json:"dryRun,omitempty"`
	}

	return json.Marshal(pinSetRequest{
		OperationRequest:    req.OperationRequest,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
}

func (s *Service) ChangePIN(ctx context.Context, req PINChangeRequest) (PINEnvelope, error) {
	meta, result, err := runTypedOperation[model.PINOutput](s, ctx, req.OperationRequest, model.ChangePINOperation{
		CurrentPIN:          req.CurrentPIN,
		NewPIN:              req.NewPIN,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
	return PINEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (req PINChangeRequest) MarshalJSON() ([]byte, error) {
	type pinChangeRequest struct {
		OperationRequest
		Confirmed           bool   `json:"confirmed,omitempty"`
		ConfirmationMessage string `json:"confirmationMessage,omitempty"`
		DryRun              bool   `json:"dryRun,omitempty"`
	}

	return json.Marshal(pinChangeRequest{
		OperationRequest:    req.OperationRequest,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
}

func (s *Service) SetAlwaysUV(ctx context.Context, req AlwaysUVRequest) (AuthenticatorConfigEnvelope, error) {
	meta, result, err := runTypedOperation[model.AuthenticatorConfigOutput](s, ctx, req.OperationRequest, model.SetAlwaysUVOperation{
		Target:              req.Target,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
	return AuthenticatorConfigEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) SetMinPINLength(ctx context.Context, req MinPINLengthRequest) (AuthenticatorConfigEnvelope, error) {
	meta, result, err := runTypedOperation[model.AuthenticatorConfigOutput](s, ctx, req.OperationRequest, model.SetMinPINLengthOperation{
		Length:              req.NewMinPINLength,
		RPIDs:               req.MinPinLengthRPIDs,
		ForceChangePin:      req.ForceChangePin,
		PinComplexityPolicy: req.PinComplexityPolicy,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
	return AuthenticatorConfigEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) BioSensorInfo(ctx context.Context, req OperationRequest) (BioSensorEnvelope, error) {
	meta, result, err := runTypedOperation[model.BioSensorOutput](s, ctx, req, model.BioSensorInfoOperation{})
	return BioSensorEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) BioList(ctx context.Context, req OperationRequest) (BioListEnvelope, error) {
	meta, result, err := runTypedOperation[model.BioListOutput](s, ctx, req, model.BioListOperation{})
	return BioListEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) BioEnroll(ctx context.Context, req BioEnrollRequest) (BioEnrollEnvelope, error) {
	meta, result, err := runTypedOperation[model.BioEnrollOutput](s, ctx, req.OperationRequest, model.BioEnrollOperation{
		TimeoutMilliseconds: req.TimeoutMilliseconds,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
	return BioEnrollEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) BioRename(ctx context.Context, req BioRenameRequest) (BioMutationEnvelope, error) {
	meta, result, err := runTypedOperation[model.BioMutationOutput](s, ctx, req.OperationRequest, model.BioRenameOperation{
		TemplateIDHex:       req.TemplateIDHex,
		FriendlyName:        req.FriendlyName,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
	return BioMutationEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) BioRemove(ctx context.Context, req BioRemoveRequest) (BioMutationEnvelope, error) {
	meta, result, err := runTypedOperation[model.BioMutationOutput](s, ctx, req.OperationRequest, model.BioRemoveOperation{
		TemplateIDHex:       req.TemplateIDHex,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
	return BioMutationEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) ResetFactory(ctx context.Context, req ResetFactoryRequest) (ResetFactoryEnvelope, error) {
	meta, result, err := runTypedOperation[model.ResetFactoryOutput](s, ctx, req.OperationRequest, model.ResetFactoryOperation{
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
	return ResetFactoryEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) MakeCredential(ctx context.Context, req MakeCredentialRequest) (MakeCredentialEnvelope, error) {
	meta, result, err := runTypedOperation[model.MakeCredentialOutput](s, ctx, req.OperationRequest, model.MakeCredentialOperation{
		MakeCredentialInput: req.MakeCredentialInput,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
	return MakeCredentialEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) GetAssertion(ctx context.Context, req GetAssertionRequest) (GetAssertionEnvelope, error) {
	meta, result, err := runTypedOperation[model.GetAssertionOutput](s, ctx, req.OperationRequest, model.GetAssertionOperation{
		GetAssertionInput: req.GetAssertionInput,
	})
	return GetAssertionEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}
