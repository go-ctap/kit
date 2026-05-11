package model

import "github.com/go-ctap/kit/model/report"

type SessionInfo struct {
	Device report.DeviceReport `json:"device"`
	Closed bool                `json:"closed"`
}
