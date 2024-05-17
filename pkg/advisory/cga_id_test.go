package advisory

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

const regexPattern = `^CGA(-[23456789cfghjmpqrvwx]{4}){3}$`

func TestGenerateCGAID(t *testing.T) {
	existingUIDs := make(map[string]struct{})
	numUUIDs := 10000

	// Compile the regular expression once
	regex := regexp.MustCompile(regexPattern)

	for i := 0; i < numUUIDs; i++ {
		uid, err := GenerateCGAID()
		require.NoError(t, err)

		// Test format
		require.True(t, regex.MatchString(uid))
		// Test uniqueness
		_, exists := existingUIDs[uid]
		require.False(t, exists, "Duplicate UUID generated: %s", uid)

		existingUIDs[uid] = struct{}{}
	}
}

func TestGenerateCGAIDWithSeed(t *testing.T) {
	// Compile the regular expression once
	regex := regexp.MustCompile(regexPattern)

	// Test deterministic output with a specific seed
	seed := int64(12345)
	expectedID := "CGA-556r-3q48-3w6v"

	generatedID, err := GenerateCGAIDWithSeed(seed)
	require.NoError(t, err, "Error generating CGA ID")

	require.Equal(t, expectedID, generatedID, "CGA ID does not match expected output for seed %d", seed)

	// Test format with a specific seed
	require.True(t, regex.MatchString(generatedID), "CGA ID does not match format: %s", generatedID)
}

func TestGenerateCGAIDFormat(t *testing.T) {
	// Compile the regular expression once
	regex := regexp.MustCompile(regexPattern)

	// Test multiple seeds for format compliance
	seeds := []int64{12345, 54321, 67890, 98765}
	for _, seed := range seeds {
		generatedID, err := GenerateCGAIDWithSeed(seed)
		require.NoError(t, err, "Error generating CGA ID for seed %d", seed)

		require.True(t, regex.MatchString(generatedID), "CGA ID does not match format for seed %d: %s", seed, generatedID)
	}
}
