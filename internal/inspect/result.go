package inspect

import (
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/kit/internal/conformance"
	"github.com/go-ctap/kit/internal/getinfo"
	appinspect "github.com/go-ctap/kit/model/inspect"
	"github.com/go-ctap/kit/model/report"
)

func BuildResult(device report.DeviceReport, info protocol.AuthenticatorGetInfoResponse) appinspect.Result {
	result := appinspect.Result{
		Device: device,
		Info: appinspect.Info{
			AuthenticatorGetInfoResponse: info,
			Assessment:                   getinfo.Resolve(info),
			Conformance:                  conformance.EvaluateGetInfo(info),
		},
	}

	if info.UvModality != nil {
		result.Info.UVModalityLabel = info.UvModality.String()
	}

	return result
}
