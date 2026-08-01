package ctapkit

import (
	"testing"

	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/token2"
	"github.com/go-ctap/yubico"
)

func TestApplyDeviceMetadataKeepsYubicoPayload(t *testing.T) {
	serial := uint32(12345678)
	info := &yubico.DeviceInfo{
		Serial:          &serial,
		FirmwareVersion: yubico.FirmwareVersion{Major: 5, Minor: 7, Build: 1},
		FormFactor:      yubico.FormFactorUSBCNano,
	}
	device := report.DeviceReport{}

	applyDeviceMetadata(&device, deviceMetadata{Yubico: info})

	if device.VendorMetadata == nil || device.VendorMetadata.Yubico != info {
		t.Fatal("DeviceReport did not retain the Yubico provider payload")
	}
	if device.Identity == nil ||
		device.Identity.Name != "YubiKey 5C Nano" ||
		device.Identity.SerialNumber != "12345678" {
		t.Fatalf("identity = %#v", device.Identity)
	}
}

func TestApplyDeviceMetadataKeepsToken2Payload(t *testing.T) {
	metadata := &token2.DeviceInfo{
		SerialNumber: "72103654095303",
		Branding:     "Token2",
		FormFactor:   "Bio3 Dual A+C PIN+",
	}
	device := report.DeviceReport{}

	applyDeviceMetadata(&device, deviceMetadata{Token2: metadata})

	if device.VendorMetadata == nil || device.VendorMetadata.Token2 != metadata {
		t.Fatal("DeviceReport did not retain the Token2 provider payload")
	}
	if device.Identity == nil ||
		device.Identity.Name != "Token2 Bio3 Dual A+C PIN+" ||
		device.Identity.SerialNumber != "72103654095303" {
		t.Fatalf("identity = %#v", device.Identity)
	}
}
