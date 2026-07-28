package identity

import (
	"strings"

	"github.com/go-ctap/token2"
)

func token2ModelName(model token2.Model) string {
	if strings.EqualFold(strings.TrimSpace(model.Branding), "unbranded") {
		model.Branding = ""
	}

	return model.DisplayName()
}
