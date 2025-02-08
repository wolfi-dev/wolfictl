package advisory

import (
	"fmt"
	"math/rand"
	"time"
)

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
