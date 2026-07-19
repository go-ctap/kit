package service

import (
	"context"

	"github.com/go-ctap/kit/model"
	"github.com/go-ctap/kit/model/config"
	"github.com/go-ctap/kit/model/credentials"
	"github.com/go-ctap/kit/model/largeblobs"
	"github.com/go-ctap/kit/model/webauthn"
)

type OperationRequest struct {
	SelectionID      SelectionID            `json:"selectionId"`
	VerificationFlow model.VerificationFlow `json:"verificationFlow,omitempty"`
}

type CredentialListRequest struct {
	OperationRequest
}

type CredentialDeleteRequest struct {
	OperationRequest
	CredentialIDHex string `json:"credentialIdHex"`
	DryRun          bool   `json:"dryRun,omitempty"`
}

type CredentialUpdateRequest struct {
	OperationRequest
	Target          credentials.CredentialTarget `json:"target"`
	UserIDHex       string                       `json:"userIdHex,omitempty"`
	Name            string                       `json:"name,omitempty"`
	DisplayName     string                       `json:"displayName,omitempty"`
	UserIDProvided  bool                         `json:"userIdProvided,omitempty"`
	NameProvided    bool                         `json:"nameProvided,omitempty"`
	DisplayProvided bool                         `json:"displayProvided,omitempty"`
	DryRun          bool                         `json:"dryRun,omitempty"`
}

type LargeBlobReadRequest struct {
	OperationRequest
	CredentialIDHex string                `json:"credentialIdHex"`
	DecodeMode      largeblobs.DecodeMode `json:"decodeMode,omitempty"`
}

type LargeBlobListRequest struct {
	OperationRequest
}

type LargeBlobMutationRequest struct {
	OperationRequest
	CredentialIDHex string `json:"credentialIdHex"`
	Payload         []byte `json:"payload,omitempty"`
	DryRun          bool   `json:"dryRun,omitempty"`
}

type LargeBlobGarbageCollectRequest struct {
	OperationRequest
	DryRun bool `json:"dryRun,omitempty"`
}

type PINSetRequest struct {
	OperationRequest
	// NewPIN participates in JSON transport. Consumers own redaction at the
	// application boundary and must not log or persist serialized requests.
	NewPIN string `json:"newPIN"`
	DryRun bool   `json:"dryRun,omitempty"`
}

type PINChangeRequest struct {
	OperationRequest
	// CurrentPIN and NewPIN participate in JSON transport. Consumers own
	// redaction at the application boundary and must not log or persist them.
	CurrentPIN string `json:"currentPIN"`
	NewPIN     string `json:"newPIN"`
	DryRun     bool   `json:"dryRun,omitempty"`
}

type AlwaysUVRequest struct {
	OperationRequest
	Target config.AlwaysUVTarget `json:"target"`
	DryRun bool                  `json:"dryRun,omitempty"`
}

type MinPINLengthRequest struct {
	OperationRequest
	NewMinPINLength     *uint    `json:"newMinPINLength,omitempty"`
	MinPINLengthRPIDs   []string `json:"minPinLengthRPIDs,omitempty"`
	ForceChangePIN      bool     `json:"forceChangePin,omitempty"`
	PINComplexityPolicy bool     `json:"pinComplexityPolicy,omitempty"`
	DryRun              bool     `json:"dryRun,omitempty"`
}

type EnableLongTouchForResetRequest struct {
	OperationRequest
	DryRun bool `json:"dryRun,omitempty"`
}

type BioEnrollRequest struct {
	OperationRequest
	TimeoutMilliseconds uint `json:"timeoutMilliseconds,omitempty"`
	DryRun              bool `json:"dryRun,omitempty"`
}

type BioRenameRequest struct {
	OperationRequest
	TemplateIDHex string `json:"templateIdHex"`
	FriendlyName  string `json:"friendlyName"`
	DryRun        bool   `json:"dryRun,omitempty"`
}

type BioRemoveRequest struct {
	OperationRequest
	TemplateIDHex string `json:"templateIdHex"`
	DryRun        bool   `json:"dryRun,omitempty"`
}

type ResetFactoryRequest struct {
	OperationRequest
	DryRun bool `json:"dryRun,omitempty"`
}

type MakeCredentialRequest struct {
	OperationRequest
	webauthn.MakeCredentialInput
	DryRun bool `json:"dryRun,omitempty"`
}

type GetAssertionRequest struct {
	OperationRequest
	webauthn.GetAssertionInput
	DryRun bool `json:"dryRun,omitempty"`
}

func (s *Service) Inspect(ctx context.Context, req OperationRequest) (InspectEnvelope, error) {
	meta, result, err := runTypedOperation[model.InspectOutput](s, ctx, req, model.InspectOperation{})
	if snapshot := s.mergeInspectMetadata(req.SelectionID, result); snapshot != nil {
		s.emit(EventDiscoveryChanged, DiscoveryChangedEnvelope{
			Trigger:  DiscoveryTriggerEnriched,
			Snapshot: snapshot,
		})
	}

	return InspectEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) ListCredentials(ctx context.Context, req CredentialListRequest) (CredentialsEnvelope, error) {
	meta, result, err := runTypedOperation[model.CredentialsOutput](s, ctx, req.OperationRequest, model.ListCredentialsOperation{})
	return CredentialsEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) CredentialStoreState(ctx context.Context, req OperationRequest) (CredentialStoreStateEnvelope, error) {
	meta, result, err := runTypedOperation[model.CredentialStoreStateOutput](s, ctx, req, model.CredentialStoreStateOperation{})

	return CredentialStoreStateEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) DeleteCredential(ctx context.Context, req CredentialDeleteRequest) (CredentialDeleteEnvelope, error) {
	meta, result, err := runTypedOperation[model.CredentialDeleteOutput](s, ctx, req.OperationRequest, model.DeleteCredentialOperation{
		CredentialIDHex: req.CredentialIDHex,
		DryRun:          req.DryRun,
	})
	return CredentialDeleteEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) UpdateCredentialUser(ctx context.Context, req CredentialUpdateRequest) (CredentialUpdateEnvelope, error) {
	meta, result, err := runTypedOperation[model.CredentialUpdateOutput](s, ctx, req.OperationRequest, model.UpdateCredentialUserOperation{
		Target:          req.Target,
		UserIDHex:       req.UserIDHex,
		Name:            req.Name,
		DisplayName:     req.DisplayName,
		UserIDProvided:  req.UserIDProvided,
		NameProvided:    req.NameProvided,
		DisplayProvided: req.DisplayProvided,
		DryRun:          req.DryRun,
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

func (s *Service) ListLargeBlobs(ctx context.Context, req LargeBlobListRequest) (LargeBlobListEnvelope, error) {
	meta, result, err := runTypedOperation[model.LargeBlobListOutput](s, ctx, req.OperationRequest, model.ListLargeBlobsOperation{})
	return LargeBlobListEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) WriteLargeBlob(ctx context.Context, req LargeBlobMutationRequest) (LargeBlobMutationEnvelope, error) {
	meta, result, err := runTypedOperation[model.LargeBlobMutationOutput](s, ctx, req.OperationRequest, model.WriteLargeBlobOperation{
		CredentialIDHex: req.CredentialIDHex,
		Payload:         req.Payload,
		DryRun:          req.DryRun,
	})
	return LargeBlobMutationEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) DeleteLargeBlob(ctx context.Context, req LargeBlobMutationRequest) (LargeBlobMutationEnvelope, error) {
	meta, result, err := runTypedOperation[model.LargeBlobMutationOutput](s, ctx, req.OperationRequest, model.DeleteLargeBlobOperation{
		CredentialIDHex: req.CredentialIDHex,
		DryRun:          req.DryRun,
	})
	return LargeBlobMutationEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) GarbageCollectLargeBlobs(ctx context.Context, req LargeBlobGarbageCollectRequest) (LargeBlobMutationEnvelope, error) {
	meta, result, err := runTypedOperation[model.LargeBlobMutationOutput](s, ctx, req.OperationRequest, model.GarbageCollectLargeBlobsOperation{
		DryRun: req.DryRun,
	})
	return LargeBlobMutationEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) ConfigStatus(ctx context.Context, req OperationRequest) (ConfigStatusEnvelope, error) {
	meta, result, err := runTypedOperation[model.ConfigStatusOutput](s, ctx, req, model.ConfigStatusOperation{})
	return ConfigStatusEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) SetPIN(ctx context.Context, req PINSetRequest) (PINEnvelope, error) {
	meta, result, err := runTypedOperation[model.PINOutput](s, ctx, req.OperationRequest, model.SetPINOperation{
		NewPIN: req.NewPIN,
		DryRun: req.DryRun,
	})
	return PINEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) ChangePIN(ctx context.Context, req PINChangeRequest) (PINEnvelope, error) {
	meta, result, err := runTypedOperation[model.PINOutput](s, ctx, req.OperationRequest, model.ChangePINOperation{
		CurrentPIN: req.CurrentPIN,
		NewPIN:     req.NewPIN,
		DryRun:     req.DryRun,
	})
	return PINEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) SetAlwaysUV(ctx context.Context, req AlwaysUVRequest) (AuthenticatorConfigEnvelope, error) {
	meta, result, err := runTypedOperation[model.AuthenticatorConfigOutput](s, ctx, req.OperationRequest, model.SetAlwaysUVOperation{
		Target: req.Target,
		DryRun: req.DryRun,
	})
	return AuthenticatorConfigEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) SetMinPINLength(ctx context.Context, req MinPINLengthRequest) (AuthenticatorConfigEnvelope, error) {
	meta, result, err := runTypedOperation[model.AuthenticatorConfigOutput](s, ctx, req.OperationRequest, model.SetMinPINLengthOperation{
		NewMinPINLength:     req.NewMinPINLength,
		MinPINLengthRPIDs:   req.MinPINLengthRPIDs,
		ForceChangePIN:      req.ForceChangePIN,
		PINComplexityPolicy: req.PINComplexityPolicy,
		DryRun:              req.DryRun,
	})
	return AuthenticatorConfigEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) EnableLongTouchForReset(ctx context.Context, req EnableLongTouchForResetRequest) (AuthenticatorConfigEnvelope, error) {
	meta, result, err := runTypedOperation[model.AuthenticatorConfigOutput](s, ctx, req.OperationRequest, model.EnableLongTouchForResetOperation{
		DryRun: req.DryRun,
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
		DryRun:              req.DryRun,
	})
	return BioEnrollEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) BioRename(ctx context.Context, req BioRenameRequest) (BioMutationEnvelope, error) {
	meta, result, err := runTypedOperation[model.BioMutationOutput](s, ctx, req.OperationRequest, model.BioRenameOperation{
		TemplateIDHex: req.TemplateIDHex,
		FriendlyName:  req.FriendlyName,
		DryRun:        req.DryRun,
	})
	return BioMutationEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) BioRemove(ctx context.Context, req BioRemoveRequest) (BioMutationEnvelope, error) {
	meta, result, err := runTypedOperation[model.BioMutationOutput](s, ctx, req.OperationRequest, model.BioRemoveOperation{
		TemplateIDHex: req.TemplateIDHex,
		DryRun:        req.DryRun,
	})
	return BioMutationEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) ResetFactory(ctx context.Context, req ResetFactoryRequest) (ResetFactoryEnvelope, error) {
	meta, result, err := runTypedOperation[model.ResetFactoryOutput](s, ctx, req.OperationRequest, model.ResetFactoryOperation{
		DryRun: req.DryRun,
	})
	return ResetFactoryEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) MakeCredential(ctx context.Context, req MakeCredentialRequest) (MakeCredentialEnvelope, error) {
	meta, result, err := runTypedOperation[model.MakeCredentialOutput](s, ctx, req.OperationRequest, model.MakeCredentialOperation{
		MakeCredentialInput: req.MakeCredentialInput,
		DryRun:              req.DryRun,
	})
	return MakeCredentialEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}

func (s *Service) GetAssertion(ctx context.Context, req GetAssertionRequest) (GetAssertionEnvelope, error) {
	meta, result, err := runTypedOperation[model.GetAssertionOutput](s, ctx, req.OperationRequest, model.GetAssertionOperation{
		GetAssertionInput: req.GetAssertionInput,
		DryRun:            req.DryRun,
	})
	return GetAssertionEnvelope{OperationEnvelopeMeta: meta, Result: result}, err
}
