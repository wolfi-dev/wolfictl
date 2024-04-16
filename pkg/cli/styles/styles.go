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

	accentedLight    = lipgloss.NewStyle().Foreground(lipgloss.Color("#000000"))
	secondaryLight   = lipgloss.NewStyle().Foreground(lipgloss.Color("#444444"))
	faintLight       = lipgloss.NewStyle().Foreground(lipgloss.Color("#aaaaaa"))
	faintAccentLight = lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))
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
