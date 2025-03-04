package advisory

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	advisoryapi "chainguard.dev/sdk/proto/platform/advisory/v1"
)

// chainguardAPIURL is the public Chainguard API.
const chainguardAPIURL = "https://console-api.enforce.dev"

var DefaultIDGenerator IDGenerator = &RandomIDGenerator{}

type IDGenerator interface {
	GenerateCGAID() (string, error)
}

func GenerateCGAID() (string, error) {
	return DefaultIDGenerator.GenerateCGAID()
}

func GenerateCGAIDWithSeed(seed int64) (string, error) {
	// Allowed characters [23456789cfghjmpqrvwx]
	allowedChars := "23456789cfghjmpqrvwx"

	// Length of the required UUID parts
	partLength := 4
	totalLength := partLength * 3

	rng := rand.New(rand.NewSource(seed)) //nolint: gosec

	// Function to get a random character from allowedChars
	getRandomChar := func() byte {
		return allowedChars[rng.Intn(len(allowedChars))]
	}

	// Generate random characters
	randomChars := make([]byte, totalLength)
	for i := 0; i < totalLength; i++ {
		randomChars[i] = getRandomChar()
	}

	// Format the custom UID to match CGA(-[23456789cfghjmpqrvwx]{4}){3}
	formattedID := fmt.Sprintf("CGA-%s-%s-%s", randomChars[0:4], randomChars[4:8], randomChars[8:12])

	return formattedID, nil
}

// RandomIDGenerator generates a random CGA ID that uses the current time as the
// seed.
type RandomIDGenerator struct{}

func (g RandomIDGenerator) GenerateCGAID() (string, error) {
	seed := time.Now().UnixNano()
	return GenerateCGAIDWithSeed(seed)
}

type StaticIDGenerator struct {
	// The ID to return every time.
	ID string
}

func (s StaticIDGenerator) GenerateCGAID() (string, error) {
	return s.ID, nil
}

type staticListIDGenerator struct {
	// The set of IDs to return sequentially.
	IDs []string

	// idx is the current index of the ID to return next.
	idx int
}

func (s *staticListIDGenerator) GenerateCGAID() (string, error) {
	if len(s.IDs) == 0 {
		return "", fmt.Errorf("IDs list is empty")
	}
	id := s.IDs[s.idx]
	s.idx = (s.idx + 1) % len(s.IDs)
	return id, nil
}

func realGetAdvisoryClients(ctx context.Context) (advisoryapi.Clients, error) {
	// Create a GRPC client to communicate with the Chainguard API.
	// Passing an empty string for the token creates an anonymous client,
	// which is acceptable in this case since the ListDocuments endpoint is unauthenticated.
	return advisoryapi.NewClients(ctx, chainguardAPIURL, "")
}

var getAdvisoryClients = realGetAdvisoryClients

// cgaIDExists checks if the given CGA ID has already been assigned to an advisory.
func cgaIDExists(ctx context.Context, id string) (bool, error) {
	clients, err := getAdvisoryClients(ctx)
	if err != nil {
		return false, fmt.Errorf("constructing chainguard api client: %w", err)
	}

	docs, err := clients.SecurityAdvisory().ListDocuments(ctx, &advisoryapi.DocumentFilter{
		Cves: []string{id},
	})
	if err != nil {
		return false, fmt.Errorf("listing advisory documents: %w", err)
	}

	return len(docs.Items) > 0, nil
}
