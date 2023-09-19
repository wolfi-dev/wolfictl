package vuln

type EventPackageMatchingStarting struct {
	Package string
}

type EventPackageMatchingFinished struct {
	Package string
	Matches []Match
}

type EventPackageMatchingError struct {
	Package string
	Err     error
}

type EventMatchingFinished struct {
}
