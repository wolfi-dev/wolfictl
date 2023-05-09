package advisory

import (
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"github.com/wolfi-dev/wolfictl/pkg/configs/advisory"
)

type BuildDatabaseOptions struct {
	AdvisoryCfgs *configs.Index[advisory.Document]
}

func BuildDatabase(opts BuildDatabaseOptions) ([]byte, error) {
	// cfgs := opts.AdvisoryCfgs.Select().Configurations()

	return nil, nil
}
