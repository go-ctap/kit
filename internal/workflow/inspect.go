package workflow

import "github.com/go-ctap/kit/model"

func (r Runner) inspect() (model.InspectResult, error) {
	return model.NewInspectResult(r.env.Selected, r.infoProvider().GetInfo()), nil
}
