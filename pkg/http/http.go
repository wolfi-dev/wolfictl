package http

import (
	"net/http"

	"golang.org/x/time/rate"
)

// RLHTTPClient is a rate limited HTTP client.
type RLHTTPClient struct {
	Client      *http.Client
	Ratelimiter *rate.Limiter
}

// Do sends an HTTP request.
func (c *RLHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if err := c.Ratelimiter.Wait(req.Context()); err != nil {
		return nil, err
	}
	// The request is supplied by the caller, so the destination is theirs to
	// choose; this wrapper only adds rate limiting.
	return c.Client.Do(req) //nolint:gosec // G704: no URL is derived from untrusted input here
}

// NewClient returns a rate limited http client.
func NewClient(rl *rate.Limiter) *RLHTTPClient {
	return &RLHTTPClient{
		Client:      http.DefaultClient,
		Ratelimiter: rl,
	}
}
