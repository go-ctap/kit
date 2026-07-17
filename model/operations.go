package model

type OperationKind string

const (
	OperationInspect                  OperationKind = "inspect"
	OperationListCredentials          OperationKind = "credentials.list"
	OperationCredentialStoreState     OperationKind = "credentials.storeState"
	OperationDeleteCredential         OperationKind = "credentials.delete"
	OperationUpdateCredentialUser     OperationKind = "credentials.updateUser"
	OperationReadLargeBlob            OperationKind = "largeBlobs.read"
	OperationListLargeBlobs           OperationKind = "largeBlobs.list"
	OperationWriteLargeBlob           OperationKind = "largeBlobs.write"
	OperationDeleteLargeBlob          OperationKind = "largeBlobs.delete"
	OperationGarbageCollectLargeBlobs OperationKind = "largeBlobs.garbageCollect"
	OperationConfigStatus             OperationKind = "config.status"
	OperationBioSensorInfo            OperationKind = "config.bio.sensorInfo"
	OperationBioList                  OperationKind = "config.bio.list"
	OperationBioEnroll                OperationKind = "config.bio.enroll"
	OperationBioRename                OperationKind = "config.bio.rename"
	OperationBioRemove                OperationKind = "config.bio.remove"
	OperationResetFactory             OperationKind = "config.reset.factory"
	OperationSetPIN                   OperationKind = "config.pin.set"
	OperationChangePIN                OperationKind = "config.pin.change"
	OperationSetAlwaysUV              OperationKind = "config.alwaysUv.set"
	OperationSetMinPINLength          OperationKind = "config.minPinLength.set"
	OperationEnableLongTouchForReset  OperationKind = "config.longTouchForReset.enable"
	OperationMakeCredential           OperationKind = "webauthn.makeCredential"
	OperationGetAssertion             OperationKind = "webauthn.getAssertion"
)

type Operation interface {
	Kind() OperationKind
	IsDryRun() bool
	ctapkitOperation()
}

type InspectOperation struct{}

func (InspectOperation) Kind() OperationKind { return OperationInspect }
func (InspectOperation) IsDryRun() bool      { return false }
func (InspectOperation) ctapkitOperation()   {}
