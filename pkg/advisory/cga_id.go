package advisory

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func GenerateCGAID() (string, error) {
	// Allowed characters [23456789cfghjmpqrvwx]
	allowedChars := "23456789cfghjmpqrvwx"

	// Length of the required UUID parts
	partLength := 4
	totalLength := partLength * 3

	// Function to get a random character from allowedChars
	getRandomChar := func() (byte, error) {
		max := big.NewInt(int64(len(allowedChars)))
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return 0, err
		}
		return allowedChars[n.Int64()], nil
	}

	// Generate random characters
	randomChars := make([]byte, totalLength)
	for i := 0; i < totalLength; i++ {
		char, err := getRandomChar()
		if err != nil {
			return "", err
		}

		randomChars[i] = char
	}

	// Format the custom UID to match CGA(-[23456789cfghjmpqrvwx]{4}){3}
	formattedUUID := fmt.Sprintf("CGA-%s-%s-%s", randomChars[0:4], randomChars[4:8], randomChars[8:12])

	return formattedUUID, nil
}
