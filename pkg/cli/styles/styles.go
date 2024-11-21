package styles

import "github.com/charmbracelet/lipgloss"

var darkMode = lipgloss.HasDarkBackground()

var (
	defaultStyle = lipgloss.NewStyle()
	accented     = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffffff"))
	secondary    = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))
	faint        = lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))
	faintAccent  = lipgloss.NewStyle().Foreground(lipgloss.Color("#aaaaaa"))
	bold         = lipgloss.NewStyle().Bold(true)
	italic       = lipgloss.NewStyle().Italic(true)

	accentedLight    = lipgloss.NewStyle().Foreground(lipgloss.Color("#000000"))
	secondaryLight   = lipgloss.NewStyle().Foreground(lipgloss.Color("#444444"))
	faintLight       = lipgloss.NewStyle().Foreground(lipgloss.Color("#aaaaaa"))
	faintAccentLight = lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))

	styleSeverityNegligible      = lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))
	styleSeverityNegligibleLight = lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))
	styleSeverityLow             = lipgloss.NewStyle().Foreground(lipgloss.Color("#00ff00"))
	styleSeverityLowLight        = lipgloss.NewStyle().Foreground(lipgloss.Color("#329e15"))
	styleSeverityMedium          = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffff00"))
	styleSeverityMediumLight     = lipgloss.NewStyle().Foreground(lipgloss.Color("#cca706"))
	styleSeverityHigh            = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff9900"))
	styleSeverityHighLight       = lipgloss.NewStyle().Foreground(lipgloss.Color("#e68c05"))
	styleSeverityCritical        = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff0000"))
	styleSeverityCriticalLight   = lipgloss.NewStyle().Foreground(lipgloss.Color("#d10606"))
)

func Default() lipgloss.Style {
	return defaultStyle
}

func Accented() lipgloss.Style {
	if !darkMode {
		return accentedLight
	}
	return accented
}

func Secondary() lipgloss.Style {
	if !darkMode {
		return secondaryLight
	}
	return secondary
}

func Faint() lipgloss.Style {
	if !darkMode {
		return faintLight
	}
	return faint
}

func FaintAccent() lipgloss.Style {
	if !darkMode {
		return faintAccentLight
	}
	return faintAccent
}

func Bold() lipgloss.Style {
	return bold
}

func Italic() lipgloss.Style {
	return italic
}

func SeverityNegligible() lipgloss.Style {
	if !darkMode {
		return styleSeverityNegligibleLight
	}
	return styleSeverityNegligible
}

func SeverityLow() lipgloss.Style {
	if !darkMode {
		return styleSeverityLowLight
	}
	return styleSeverityLow
}

func SeverityMedium() lipgloss.Style {
	if !darkMode {
		return styleSeverityMediumLight
	}
	return styleSeverityMedium
}

func SeverityHigh() lipgloss.Style {
	if !darkMode {
		return styleSeverityHighLight
	}
	return styleSeverityHigh
}

func SeverityCritical() lipgloss.Style {
	if !darkMode {
		return styleSeverityCriticalLight
	}
	return styleSeverityCritical
}
