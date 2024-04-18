package wrapped

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/reflow/wordwrap"
	"golang.org/x/term"
)

var (
	// LineLength is the maximum length allowed of a printed line of text. This is
	// the primary control for this package. It defaults to the greater of the
	// current terminal width (detected at init time) and MaxLineLength.
	LineLength = initialLineLength

	// MaxLineLength sets the upper bound for how long a line can be. This is a
	// secondary control that adjusts how LineLength is calculated. It defaults to
	// 120 (for readability).
	MaxLineLength = 120
)

// Println wraps the given message using LineLength and prints it to stdout with
// a trailing newline.
func Println(msg string) {
	fmt.Println(wrapToLineLength(msg))
}

// Sprint wraps the given message using LineLength and returns it as a string.
func Sprint(msg string) string {
	return wrapToLineLength(msg)
}

// Fatal wraps the given message using LineLength and prints it to stderr with a
// trailing newline, then exits with a non-zero status code.
func Fatal(msg string) {
	fmt.Fprintln(os.Stderr, wrapToLineLength(msg))
	os.Exit(1)
}

// Repeat repeats the given message string until the LineLength is reached, such
// that the returned string is exactly LineLength long. If the given string is
// already longer than LineLength, it is truncated to LineLength.
func Repeat(s string) string {
	if length := lipgloss.Width(s); length > LineLength {
		// Repeating is not necessary.
		return truncate(s)
	}

	sb := new(strings.Builder)

	// We're using lipgloss to measure the rendered length of the string (we don't
	// want to measure the raw length of the string — some characters are rendered
	// wider than others, while others are not rendered at all).
	currentLength := lipgloss.Width(sb.String())
	for currentLength < LineLength {
		sb.WriteString(s)

		currentLength = lipgloss.Width(sb.String())
	}

	// Truncate the string to the line length.
	line := truncate(sb.String())

	return line
}

const (
	// This is only used if we can't detect the terminal width.
	fallbackLineLength = 80
)

var (
	initialLineLength = func() int {
		// Defer to smaller-width terminal screens, but don't go bigger than
		// MaxLineLength.
		if terminalWidth < MaxLineLength {
			return terminalWidth
		}

		return MaxLineLength
	}()

	terminalWidth = getTerminalWidth()
)

func getTerminalWidth() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return fallbackLineLength
	}
	return w
}

func wrapToLineLength(msg string) string {
	return wordwrap.String(msg, LineLength)
}

var styleTruncated = lipgloss.NewStyle().Width(LineLength)

func truncate(msg string) string {
	if length := lipgloss.Width(msg); length > LineLength {
		return styleTruncated.Render(msg)
	}

	return msg
}
