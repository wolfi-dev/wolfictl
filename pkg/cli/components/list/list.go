package list

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type Model struct {
	focused       bool
	prompt        string
	items         []string
	selectedIndex int

	SelectedStyle   lipgloss.Style
	UnselectedStyle lipgloss.Style
}

func New(prompt string, items []string) Model {
	return Model{
		prompt:        prompt,
		items:         items,
		selectedIndex: 0,
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (Model, tea.Cmd) {
	if msg, ok := msg.(tea.KeyMsg); ok {
		switch msg.String() {
		case "up", "k":
			if m.selectedIndex > 0 {
				m.selectedIndex--
			}

		case "down", "j":
			if m.selectedIndex < len(m.items)-1 {
				m.selectedIndex++
			}
		}
	}

	return m, nil
}

func (m Model) View() string {
	var lines []string

	lines = append(lines, m.prompt)

	for i, item := range m.items {
		var itemLine string

		if i == m.selectedIndex {
			itemLine = m.SelectedStyle.Render("> " + item)
		} else {
			itemLine = m.UnselectedStyle.Render("  " + item)
		}

		lines = append(lines, itemLine)
	}

	return strings.Join(lines, "\n")
}

func (m Model) SelectedItem() string {
	return m.items[m.selectedIndex]
}

func (m Model) Focus() Model {
	m.focused = true
	return m
}

func (m Model) Focused() bool {
	return m.focused
}

func (m Model) Blur() Model {
	m.focused = false
	return m
}
