package breather

import (
	"math"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/lucasb-eyer/go-colorful"
)

type Model struct {
	Text string

	colorVal float64
	style    lipgloss.Style
}

func New(char string) Model {
	return Model{
		Text:     char,
		colorVal: 0.5,
		style:    lipgloss.NewStyle(),
	}
}

func (m Model) Init() tea.Cmd {
	return doTick()
}

func (m Model) Update(msg tea.Msg) (Model, tea.Cmd) {
	if t, ok := msg.(TickMsg); ok {
		m.colorVal = t.sineValue()
	}

	return m, doTick()
}

func (m Model) View() string {
	c := colorful.Hsl(0, 0, m.colorVal)
	color := lipgloss.Color(c.Hex())

	return m.style.Foreground(color).Render(m.Text)
}

// ViewStatic returns the view without any animations.
func (m Model) ViewStatic() string {
	return m.style.Render(m.Text)
}

type TickMsg time.Time

func (t TickMsg) sineValue() float64 {
	unix := float64(time.Time(t).UnixNano()) / 1e9 // Convert to seconds

	return cycleAmplitude*math.Sin(unix*math.Pi*2/cycleLengthInSeconds) + cycleMidpoint
}

func doTick() tea.Cmd {
	return tea.Tick(tickLength, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

const (
	tickLength = 33 * time.Millisecond

	cycleLengthInSeconds = 2.3
	cycleMidpoint        = 0.55
	cycleAmplitude       = 0.2
)
