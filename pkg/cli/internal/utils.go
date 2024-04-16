package internal

// SelectPlurality returns the singular or plural form of a word based on the
// count.
func SelectPlurality(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}
