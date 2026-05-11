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

func (s *Service) Inspect(ctx context.Context, req OperationRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req, model.InspectOperation{})
}

func (s *Service) ListCredentials(ctx context.Context, req OperationRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req, model.ListCredentialsOperation{})
}

func (s *Service) DeleteCredential(ctx context.Context, req CredentialDeleteRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req.OperationRequest, model.DeleteCredentialOperation{
		CredentialIDHex:     req.CredentialIDHex,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
}

func (s *Service) UpdateCredentialUser(ctx context.Context, req CredentialUpdateRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req.OperationRequest, model.UpdateCredentialUserOperation{
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
}

func (s *Service) ReadLargeBlob(ctx context.Context, req LargeBlobReadRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req.OperationRequest, model.ReadLargeBlobOperation{
		CredentialIDHex: req.CredentialIDHex,
		DecodeMode:      req.DecodeMode,
	})
}

func (s *Service) ListLargeBlobs(ctx context.Context, req OperationRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req, model.ListLargeBlobsOperation{})
}

func (s *Service) WriteLargeBlob(ctx context.Context, req LargeBlobMutationRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req.OperationRequest, model.WriteLargeBlobOperation{
		CredentialIDHex:     req.CredentialIDHex,
		Payload:             req.Payload,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
}

func (s *Service) DeleteLargeBlob(ctx context.Context, req LargeBlobMutationRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req.OperationRequest, model.DeleteLargeBlobOperation{
		CredentialIDHex:     req.CredentialIDHex,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
}

func (s *Service) GarbageCollectLargeBlobs(ctx context.Context, req LargeBlobGarbageCollectRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req.OperationRequest, model.GarbageCollectLargeBlobsOperation{
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
}

func (s *Service) ConfigStatus(ctx context.Context, req OperationRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req, model.ConfigStatusOperation{})
}

func (s *Service) SetPIN(ctx context.Context, req PINSetRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req.OperationRequest, model.SetPINOperation{
		NewPIN:              req.NewPIN,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
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

func (s *Service) ChangePIN(ctx context.Context, req PINChangeRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req.OperationRequest, model.ChangePINOperation{
		CurrentPIN:          req.CurrentPIN,
		NewPIN:              req.NewPIN,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
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

func (s *Service) SetAlwaysUV(ctx context.Context, req AlwaysUVRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req.OperationRequest, model.SetAlwaysUVOperation{
		Target:              req.Target,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
}

func (s *Service) SetMinPINLength(ctx context.Context, req MinPINLengthRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req.OperationRequest, model.SetMinPINLengthOperation{
		Length:              req.NewMinPINLength,
		RPIDs:               req.MinPinLengthRPIDs,
		ForceChangePin:      req.ForceChangePin,
		PinComplexityPolicy: req.PinComplexityPolicy,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
}

func (s *Service) BioSensorInfo(ctx context.Context, req OperationRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req, model.BioSensorInfoOperation{})
}

func (s *Service) BioList(ctx context.Context, req OperationRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req, model.BioListOperation{})
}

func (s *Service) BioEnroll(ctx context.Context, req BioEnrollRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req.OperationRequest, model.BioEnrollOperation{
		TimeoutMilliseconds: req.TimeoutMilliseconds,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
}

func (s *Service) BioRename(ctx context.Context, req BioRenameRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req.OperationRequest, model.BioRenameOperation{
		TemplateIDHex:       req.TemplateIDHex,
		FriendlyName:        req.FriendlyName,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
}

func (s *Service) BioRemove(ctx context.Context, req BioRemoveRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req.OperationRequest, model.BioRemoveOperation{
		TemplateIDHex:       req.TemplateIDHex,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
}

func (s *Service) ResetFactory(ctx context.Context, req ResetFactoryRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req.OperationRequest, model.ResetFactoryOperation{
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
}

func (s *Service) MakeCredential(ctx context.Context, req MakeCredentialRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req.OperationRequest, model.MakeCredentialOperation{
		MakeCredentialInput: req.MakeCredentialInput,
		Confirmed:           req.Confirmed,
		ConfirmationMessage: req.ConfirmationMessage,
		DryRun:              req.DryRun,
	})
}

func (s *Service) GetAssertion(ctx context.Context, req GetAssertionRequest) (OperationEnvelope, error) {
	return s.runOperation(ctx, req.OperationRequest, model.GetAssertionOperation{
		GetAssertionInput: req.GetAssertionInput,
	})
}
