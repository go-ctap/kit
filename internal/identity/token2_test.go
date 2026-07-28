package identity

import (
	"testing"

	"github.com/go-ctap/token2"
)

func TestToken2ModelNameOmitsOnlyGenericUnbrandedMarker(t *testing.T) {
	tests := []struct {
		branding string
		want     string
	}{
		{branding: "Token2", want: "Token2 Dual NFC PIN+ PIV+"},
		{branding: "Unbranded", want: "Dual NFC PIN+ PIV+"},
		{branding: "Unbranded Octo", want: "Unbranded Octo Dual NFC PIN+ PIV+"},
	}
	for _, test := range tests {
		model := token2.Model{
			Branding:   test.branding,
			FormFactor: "Dual NFC PIN+ PIV+",
		}
		if got := token2ModelName(model); got != test.want {
			t.Errorf("token2ModelName(%q) = %q, want %q", test.branding, got, test.want)
		}
	}
}
