package advisory

import (
	"errors"

	"github.com/samber/lo"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
)

type ValidateOptions struct {
	// AdvisoryCfgs is the Index of advisories on which to operate.
	AdvisoryCfgs *configs.Index[v2.Document]
}

func Validate(opts ValidateOptions) error {
	documents := opts.AdvisoryCfgs.Select().Configurations()

	return errors.Join(lo.Map(documents, func(doc v2.Document, _ int) error {
		return doc.Validate()
	})...)
}
