package transport

import (
	ghid "github.com/go-ctap/hid"
	"github.com/samber/lo"
)

func descriptorsFromDeviceInfos(mode Mode, infos []*ghid.DeviceInfo) []Descriptor {
	return lo.Map(infos, func(info *ghid.DeviceInfo, _ int) Descriptor {
		return Descriptor{
			Transport:    mode,
			Path:         info.Path,
			Manufacturer: info.MfrStr,
			Product:      info.ProductStr,
			Serial:       info.SerialNbr,
			VendorID:     info.VendorID,
			ProductID:    info.ProductID,
			UsagePage:    info.UsagePage,
			Usage:        info.Usage,
		}
	})
}
