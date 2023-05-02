package field

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
)

type Field interface {
	View() string
	IsDone() bool
	Value() string

	SetDone() Field
	SetBlur() Field
	SetFocus() (Field, tea.Cmd)
	Update(tea.Msg) (Field, tea.Cmd)
	UpdateRequest(value string, request advisory.Request) advisory.Request
}

var (
	focusedStyle        = lipgloss.NewStyle()
	blurredStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	cursorStyle         = focusedStyle.Copy()
	noStyle             = lipgloss.NewStyle()
	helpStyle           = blurredStyle.Copy()
	cursorModeHelpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
)
