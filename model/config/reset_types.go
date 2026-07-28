package config

import (
	"github.com/go-ctap/kit/model/report"
	"github.com/go-ctap/kit/model/safety"
)

type ResetPreview struct {
	Device     report.DeviceReport `json:"device"`
	ResetHints ResetHints          `json:"resetHints"`
	Mode       safety.PreviewMode  `json:"mode"`
	Warnings   []safety.Warning    `json:"warnings,omitempty"`
}

type ResetResult struct {
	AttachmentID report.AttachmentID `json:"attachmentId"`
	Reset        bool                `json:"reset"`
}
