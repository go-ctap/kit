package ctapkit

import (
	"bytes"
	"encoding/hex"

	rtdevice "github.com/go-ctap/kit/internal/device"
	"github.com/go-ctap/kit/internal/discovery"
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/transport"
)

type attachment struct {
	descriptor discovery.Descriptor
	report     report.DeviceReport
}

func attachmentReport(descriptor discovery.Descriptor) report.AttachmentReport {
	attachment := report.AttachmentReport{
		ID:        report.AttachmentID(rtdevice.AttachmentID(descriptor)),
		Transport: descriptor.Transport,
	}
	if descriptor.Transport == transport.ModeSmartCard {
		attachment.SmartCard = &report.SmartCardReport{
			Reader: descriptor.Path,
			ATR:    hex.EncodeToString(descriptor.ATR),
		}
	} else {
		attachment.USB = &report.USBReport{
			Manufacturer:   descriptor.Manufacturer,
			Product:        descriptor.Product,
			ReportedSerial: descriptor.Serial,
			VendorID:       descriptor.VendorID,
			ProductID:      descriptor.ProductID,
		}
	}

	return attachment
}

func sameConnection(current, next discovery.Descriptor) bool {
	return current.Transport == next.Transport &&
		current.Path == next.Path &&
		current.Manufacturer == next.Manufacturer &&
		current.Product == next.Product &&
		current.Serial == next.Serial &&
		current.VendorID == next.VendorID &&
		current.ProductID == next.ProductID &&
		bytes.Equal(current.ATR, next.ATR) &&
		current.InstanceID == next.InstanceID &&
		current.ParentDeviceID == next.ParentDeviceID
}
