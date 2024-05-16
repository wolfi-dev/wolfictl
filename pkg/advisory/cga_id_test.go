package advisory

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateCGAID(t *testing.T) {
	existingUIDs := make(map[string]struct{})
	numUUIDs := 10000

	// Compile the regular expression once
	regexPattern := `^CGA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$`
	regex, err := regexp.Compile(regexPattern)
	require.NoError(t, err)

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
