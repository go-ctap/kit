package ctapkit

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"reflect"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/cose"
	"github.com/go-ctap/ctap/protocol"
	appwebauthn "github.com/go-ctap/kit/model/webauthn"
)

type attestationObject struct {
	Format    attestation.AttestationStatementFormatIdentifier `cbor:"fmt"`
	AuthData  []byte                                           `cbor:"authData"`
	Statement map[string]any                                   `cbor:"attStmt"`
}

func VerifyMakeCredential(
	input appwebauthn.MakeCredentialInput,
	result appwebauthn.MakeCredentialResult,
) appwebauthn.MakeCredentialVerification {
	outcome := newVerificationOutcome()
	verification := appwebauthn.MakeCredentialVerification{
		Status:            appwebauthn.VerificationStatusVerified,
		AttestationFormat: result.Format,
		AttestationType:   appwebauthn.AttestationTypeUnsupported,
	}

	if result.RPID != input.RP.ID {
		outcome.fail(appwebauthn.VerificationIssueResultRPIDMismatch)
	}

	authDataRaw, err := hex.DecodeString(result.AuthenticatorDataHex)
	if err != nil {
		outcome.fail(appwebauthn.VerificationIssueResultMalformed)
		return finishMakeCredentialVerification(verification, outcome)
	}
	authData, err := protocol.ParseMakeCredentialAuthData(authDataRaw)
	if err != nil {
		outcome.fail(appwebauthn.VerificationIssueAuthenticatorDataMalformed)
		return finishMakeCredentialVerification(verification, outcome)
	}

	expectedRPIDHash := sha256.Sum256([]byte(input.RP.ID))
	verification.RPIDHashMatches = bytes.Equal(authData.RPIDHash, expectedRPIDHash[:])
	if !verification.RPIDHashMatches {
		outcome.fail(appwebauthn.VerificationIssueRPIDHashMismatch)
	}
	verification.UserPresenceRequirementMet = requirementMet(
		optionRequired(input.Options.UserPresence, true),
		authData.Flags.UserPresent(),
	)
	if !verification.UserPresenceRequirementMet {
		outcome.fail(appwebauthn.VerificationIssueUserPresenceMissing)
	}
	verification.UserVerificationRequirementMet = requirementMet(
		optionRequired(input.Options.UserVerification, false),
		authData.Flags.UserVerified(),
	)
	if !verification.UserVerificationRequirementMet {
		outcome.fail(appwebauthn.VerificationIssueUserVerificationMissing)
	}

	if authData.AttestedCredentialData == nil {
		outcome.fail(appwebauthn.VerificationIssueAttestedCredentialDataMissing)
		return finishMakeCredentialVerification(verification, outcome)
	}
	attested := authData.AttestedCredentialData
	if !makeCredentialResultMatches(result, authData, attested.CredentialID, attested.CredentialPublicKey) {
		outcome.fail(appwebauthn.VerificationIssueResultMismatch)
	}

	algorithm, err := attested.CredentialPublicKey.Algorithm()
	if err != nil {
		outcome.fail(appwebauthn.VerificationIssueCredentialKeyMalformed)
		return finishMakeCredentialVerification(verification, outcome)
	}
	verification.CredentialAlgorithmAllowed = algorithmAllowed(input.PubKeyCredParams, algorithm)
	if !verification.CredentialAlgorithmAllowed {
		outcome.fail(appwebauthn.VerificationIssueCredentialAlgorithmDisallowed)
	}

	credentialPublicKey, err := attested.CredentialPublicKey.PublicKey()
	if err != nil {
		if unsupportedCrypto(err) {
			outcome.unavailable(appwebauthn.VerificationIssueCredentialAlgorithmUnsupported)
		} else {
			outcome.fail(appwebauthn.VerificationIssueCredentialKeyMalformed)
		}
		return finishMakeCredentialVerification(verification, outcome)
	}

	object, ok := parseAttestationObject(result.AttestationObjectCBORHex)
	if !ok {
		outcome.fail(appwebauthn.VerificationIssueAttestationObjectMalformed)
		return finishMakeCredentialVerification(verification, outcome)
	}
	if object.Format != result.Format || !bytes.Equal(object.AuthData, authDataRaw) {
		outcome.fail(appwebauthn.VerificationIssueAttestationObjectMismatch)
	}
	verification.AttestationFormat = object.Format

	clientDataHash := sha256.Sum256(input.ClientDataJSON)
	signedData := make([]byte, 0, len(authDataRaw)+len(clientDataHash))
	signedData = append(signedData, authDataRaw...)
	signedData = append(signedData, clientDataHash[:]...)
	response := protocol.AuthenticatorMakeCredentialResponse{AttestationStatement: object.Statement}

	switch object.Format {
	case attestation.AttestationStatementFormatIdentifierPacked:
		verifyPackedAttestation(
			&verification,
			&outcome,
			response,
			credentialPublicKey,
			algorithm,
			signedData,
		)
	case attestation.AttestationStatementFormatIdentifierFIDOU2F:
		verifyFIDOU2FAttestation(
			&verification,
			&outcome,
			response,
			credentialPublicKey,
			algorithm,
			authData.RPIDHash,
			clientDataHash[:],
			attested.CredentialID,
		)
	case attestation.AttestationStatementFormatIdentifierNone:
		verification.AttestationType = appwebauthn.AttestationTypeNone
		if len(object.Statement) != 0 {
			outcome.fail(appwebauthn.VerificationIssueAttestationStatementMalformed)
		}
	default:
		verification.AttestationType = appwebauthn.AttestationTypeUnsupported
		outcome.unavailable(appwebauthn.VerificationIssueAttestationFormatUnsupported)
	}

	return finishMakeCredentialVerification(verification, outcome)
}

func parseAttestationObject(value string) (attestationObject, bool) {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return attestationObject{}, false
	}
	reader := bytes.NewReader(raw)
	decoder := cbor.NewDecoder(reader)
	var object attestationObject
	if err := decoder.Decode(&object); err != nil || reader.Len() != 0 {
		return attestationObject{}, false
	}
	if object.Format == "" || object.AuthData == nil || object.Statement == nil {
		return attestationObject{}, false
	}

	return object, true
}

func makeCredentialResultMatches(
	result appwebauthn.MakeCredentialResult,
	authData protocol.MakeCredentialAuthData,
	credentialID []byte,
	credentialKey cose.Key,
) bool {
	resultCredentialID, err := hex.DecodeString(result.CredentialIDHex)
	if err != nil || !bytes.Equal(resultCredentialID, credentialID) {
		return false
	}
	resultKey, err := decodeCredentialKeyHex(result.PublicKeyCOSEHex)
	if err != nil || !reflect.DeepEqual(resultKey, credentialKey) {
		return false
	}

	return result.SignCount == authData.SignCount &&
		result.UserPresent == authData.Flags.UserPresent() &&
		result.UserVerified == authData.Flags.UserVerified() &&
		result.AAGUID == authData.AttestedCredentialData.AAGUID.String()
}

func verifyPackedAttestation(
	verification *appwebauthn.MakeCredentialVerification,
	outcome *verificationOutcome,
	response protocol.AuthenticatorMakeCredentialResponse,
	credentialPublicKey crypto.PublicKey,
	credentialAlgorithm cose.Algorithm,
	signedData []byte,
) {
	statement, ok := response.PackedAttestationStatementFormat()
	if !ok {
		outcome.fail(appwebauthn.VerificationIssueAttestationStatementMalformed)
		return
	}
	if _, ecdaa := response.AttestationStatement["ecdaaKeyId"]; ecdaa {
		verification.AttestationType = appwebauthn.AttestationTypeUnsupported
		outcome.unavailable(appwebauthn.VerificationIssueAttestationFormatUnsupported)
		return
	}

	if len(statement.X509Chain) == 0 {
		verification.AttestationType = appwebauthn.AttestationTypeSelf
		if statement.Algorithm != credentialAlgorithm {
			outcome.fail(appwebauthn.VerificationIssueAttestationStatementMalformed)
			return
		}
		verification.SignatureValid = verifySignature(
			outcome,
			credentialPublicKey,
			statement.Algorithm,
			signedData,
			statement.Signature,
			appwebauthn.VerificationIssueAttestationSignatureInvalid,
		)

		return
	}

	verification.AttestationType = appwebauthn.AttestationTypeBasic
	leaf, err := x509.ParseCertificate(statement.X509Chain[0])
	if err != nil {
		outcome.fail(appwebauthn.VerificationIssueAttestationStatementMalformed)
		return
	}
	verification.SignatureValid = verifySignature(
		outcome,
		leaf.PublicKey,
		statement.Algorithm,
		signedData,
		statement.Signature,
		appwebauthn.VerificationIssueAttestationSignatureInvalid,
	)
}

func verifyFIDOU2FAttestation(
	verification *appwebauthn.MakeCredentialVerification,
	outcome *verificationOutcome,
	response protocol.AuthenticatorMakeCredentialResponse,
	credentialPublicKey crypto.PublicKey,
	credentialAlgorithm cose.Algorithm,
	rpIDHash []byte,
	clientDataHash []byte,
	credentialID []byte,
) {
	verification.AttestationType = appwebauthn.AttestationTypeBasic
	statement, ok := response.FIDOU2FAttestationStatementFormat()
	if !ok || len(statement.X509Chain) == 0 {
		outcome.fail(appwebauthn.VerificationIssueAttestationStatementMalformed)
		return
	}
	key, ok := credentialPublicKey.(*ecdsa.PublicKey)
	if !ok || credentialAlgorithm != cose.AlgorithmES256 {
		outcome.fail(appwebauthn.VerificationIssueAttestationStatementMalformed)
		return
	}
	encodedKey, err := key.Bytes()
	if err != nil {
		outcome.fail(appwebauthn.VerificationIssueCredentialKeyMalformed)
		return
	}

	signedData := make([]byte, 0, 1+len(rpIDHash)+len(clientDataHash)+len(credentialID)+len(encodedKey))
	signedData = append(signedData, 0)
	signedData = append(signedData, rpIDHash...)
	signedData = append(signedData, clientDataHash...)
	signedData = append(signedData, credentialID...)
	signedData = append(signedData, encodedKey...)
	leaf, err := x509.ParseCertificate(statement.X509Chain[0])
	if err != nil {
		outcome.fail(appwebauthn.VerificationIssueAttestationStatementMalformed)
		return
	}
	verification.SignatureValid = verifySignature(
		outcome,
		leaf.PublicKey,
		cose.AlgorithmES256,
		signedData,
		statement.Signature,
		appwebauthn.VerificationIssueAttestationSignatureInvalid,
	)
}

func finishMakeCredentialVerification(
	verification appwebauthn.MakeCredentialVerification,
	outcome verificationOutcome,
) appwebauthn.MakeCredentialVerification {
	verification.Status = outcome.status
	verification.Issues = outcome.issues

	return verification
}
