package ctap23

import (
	"context"
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

var allowedUVMethods = protocol.UserVerifyFingerprintInternal |
	protocol.UserVerifyVoiceprintInternal |
	protocol.UserVerifyFaceprintInternal |
	protocol.UserVerifyEyeprintInternal |
	protocol.UserVerifyHandprintInternal |
	protocol.UserVerifyPatternInternal |
	protocol.UserVerifyPatternExternal |
	protocol.UserVerifyPasscodeInternal |
	protocol.UserVerifyPasscodeExternal

func getInfoOptionsTest(metadata Metadata) conformance.Test {
	reference := getInfoReference()

	return conformance.Test{
		ID:          TestIDAuthrGeneric1P2,
		Name:        "GetInfo options and metadata verification methods",
		Description: "Checks option wire types and the metadata verification methods implied by UP and UV capabilities",
		Source: conformance.SourceLocation{
			Path: getInfoSourcePath,
			Case: "P-2",
		},
		References: []conformance.RequirementRef{reference},
		Run: func(test *conformance.TestContext) {
			test.Step(conformance.Step{
				ID:         "get-info.options-metadata",
				Name:       "Validate options against metadata verification methods",
				References: []conformance.RequirementRef{reference},
				Run: func(ctx context.Context) error {
					_, info, err := readGetInfo(ctx, test.CBOR())
					if err != nil {
						return err
					}

					up, hasUP := info.Options[protocol.OptionUserPresence]
					if (!hasUP || up) && !hasVerificationMethod(metadata, protocol.UserVerifyPresenceInternal) {
						return conformance.Fail("metadata is missing presence_internal for user presence")
					}

					uv := info.Options[protocol.OptionUserVerification]
					if uv && !hasVerificationMethod(metadata, allowedUVMethods) {
						return conformance.Fail("metadata is missing a supported internal or external user verification method")
					}

					if hasUP && !up && !uv && !hasVerificationMethod(metadata, protocol.UserVerifyNone) {
						return conformance.Fail("metadata is missing none for an authenticator without UP or UV")
					}

					return nil
				},
			})
		},
	}
}

func getInfoPinUvAuthProtocolsTest(metadata Metadata) conformance.Test {
	reference := getInfoReference()

	return conformance.Test{
		ID:          TestIDAuthrGeneric1P3,
		Name:        "PIN/UV protocols and metadata verification method",
		Description: "Requires passcode_external metadata when GetInfo advertises PIN/UV authentication protocols",
		Source: conformance.SourceLocation{
			Path: getInfoSourcePath,
			Case: "P-3",
		},
		References: []conformance.RequirementRef{reference},
		Run: func(test *conformance.TestContext) {
			test.Step(conformance.Step{
				ID:         "get-info.pin-uv-auth-protocols-metadata",
				Name:       "Validate PIN/UV protocol metadata",
				References: []conformance.RequirementRef{reference},
				Run: func(ctx context.Context) error {
					_, info, err := readGetInfo(ctx, test.CBOR())
					if err != nil {
						return err
					}
					if len(info.PinUvAuthProtocols) == 0 {
						return conformance.Skip("authenticator does not advertise PIN/UV authentication protocols")
					}
					if !hasVerificationMethod(metadata, protocol.UserVerifyPasscodeExternal) {
						return conformance.Fail("metadata is missing passcode_external for PIN/UV authentication protocols")
					}

					return nil
				},
			})
		},
	}
}

func hasVerificationMethod(metadata Metadata, methods protocol.UserVerify) bool {
	return metadata.UserVerificationMethods&methods != 0
}

func readGetInfo(
	ctx context.Context,
	device ctaptransport.CBOR,
) (map[uint64]cbor.RawMessage, protocol.AuthenticatorGetInfoResponse, error) {
	response, err := device.CBOR(ctx, []byte{byte(protocol.AuthenticatorGetInfo)})
	if err != nil {
		var ctapErr *ctaptransport.CTAPError
		if errors.As(err, &ctapErr) {
			return nil, protocol.AuthenticatorGetInfoResponse{}, conformance.Failf(
				"authenticatorGetInfo returned %s",
				ctapErr.StatusCode,
			)
		}

		return nil, protocol.AuthenticatorGetInfoResponse{}, err
	}
	if response.StatusCode != ctaptransport.CTAP2_OK {
		return nil, protocol.AuthenticatorGetInfoResponse{}, conformance.Failf(
			"authenticatorGetInfo returned %s",
			response.StatusCode,
		)
	}

	fields, info, err := decodeGetInfoResponse(response.Data)
	if err != nil {
		return nil, protocol.AuthenticatorGetInfoResponse{}, conformance.Failf(
			"invalid authenticatorGetInfo CBOR: %v",
			err,
		)
	}

	return fields, info, nil
}
