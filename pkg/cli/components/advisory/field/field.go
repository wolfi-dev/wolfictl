package field

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
)

type Field interface {
	ID() string
	View() string
	IsDone() bool
	Value() string

	SetBlur() Field
	SetFocus() (Field, tea.Cmd)
	Update(tea.Msg) (Field, tea.Cmd)
	UpdateRequest(request advisory.Request) advisory.Request
	SubmitValue() (Field, error)
}

type ErrValueNotAccepted struct {
	Value  string
	Reason error
}

func (e ErrValueNotAccepted) Error() string {
	return fmt.Sprintf("entered value %q is not accepted: %s", e.Value, e.Reason.Error())
}
