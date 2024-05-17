package advisory

import (
	"fmt"
	"math/rand"
	"time"
)

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

func GenerateCGAID() (string, error) {
	seed := time.Now().UnixNano()

	return GenerateCGAIDWithSeed(seed)
}
