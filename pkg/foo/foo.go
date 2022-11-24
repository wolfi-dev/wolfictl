package foo

import (
	"golang.org/x/time/rate"
	"log"
	"net/http"
	"time"
)

type Context struct {
	OutDir string
	Client *RLHTTPClient
	Logger *log.Logger
}

// New initialise including a map of existing wolfios packages
func New() (Context, error) {
	context := Context{

		Client: &RLHTTPClient{
			client: http.DefaultClient,

			// 1 request every second to avoid DOS'ing server
			Ratelimiter: rate.NewLimiter(rate.Every(1*time.Second), 1),
		},
		Logger: log.New(log.Writer(), "mconvert: ", log.LstdFlags|log.Lmsgprefix),
	}

	//req, _ := http.NewRequest("GET", wolfios.WolfiosPackageRepository, nil)
	//resp, err := context.Client.Do(req)
	//
	//if err != nil {
	//	return context, errors.Wrapf(err, "failed getting URI %s", wolfios.WolfiosPackageRepository)
	//}
	//defer resp.Body.Close()
	//
	//if resp.StatusCode != http.StatusOK {
	//	return context, fmt.Errorf("non ok http response for URI %s code: %v", wolfios.WolfiosPackageRepository, resp.StatusCode)
	//}
	//
	//b, err := io.ReadAll(resp.Body)
	//if err != nil {
	//	return context, errors.Wrap(err, "reading APKBUILD file")
	//}

	// keep the map of wolfi packages on the main struct so it's easy to check if we already have any ABKBUILD dependencies
	//context.WolfiOSPackages, err = wolfios.ParseWolfiPackages(b)
	//if err != nil {
	//	return context, errors.Wrapf(err, "parsing wolfi packages")
	//}

	return context, nil
}
