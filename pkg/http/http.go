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
	return c.Client.Do(req)
}

// NewClient returns a rate limited http client.
func NewClient(rl *rate.Limiter) *RLHTTPClient {
	return &RLHTTPClient{
		Client:      http.DefaultClient,
		Ratelimiter: rl,
	}
}
