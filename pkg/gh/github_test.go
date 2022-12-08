package gh

import (
	"log"
	"testing"
)

func TestGitOptions_isPullRequestOldVersion(t *testing.T) {

	o := GitOptions{
		Logger: log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix),
	}

	tests := []struct {
		packageName    string
		packageVersion string
		prTitle        string
		want           bool
	}{
		{packageName: "cheese", packageVersion: "1.2.3", prTitle: "a random pull request", want: false},
		{packageName: "cheese", packageVersion: "1.2.3", prTitle: "cheese", want: false},
		{packageName: "cheese", packageVersion: "1.2.3", prTitle: "cheese/ ", want: false},
		{packageName: "wine", packageVersion: "1.2.3", prTitle: "cheese/ ", want: false},
		{packageName: "cheese", packageVersion: "1.2.3", prTitle: "cheese/ many / ", want: false},
		{packageName: "cheese", packageVersion: "1.2.3", prTitle: "cheese/ cheese/ many ", want: false},
		{packageName: "cheese", packageVersion: "1.2.3", prTitle: "cheese/ cheese/ many ", want: false},
		{packageName: "cheese", packageVersion: "abcde", prTitle: "cheese/1.2.3", want: false},
		{packageName: "cheese", packageVersion: "abcde", prTitle: "cheese/1.2.3 update", want: false},
		{packageName: "cheese", packageVersion: "1.2.3", prTitle: "cheese/abcde update", want: false},
		{packageName: "cheese", packageVersion: "1.2.3", prTitle: "cheese/1.2.3 update", want: false},
		{packageName: "cheese", packageVersion: "1.2.3", prTitle: "cheese/1.2.4 update", want: false},
		{packageName: "wine", packageVersion: "1.2.3", prTitle: "cheese/1.2.2 update", want: false},
		{packageName: "cheese", packageVersion: "1.2.3", prTitle: "cheese/1.2.2 update", want: true},
	}
	for _, tt := range tests {
		t.Run("", func(t *testing.T) {

			if got := o.isPullRequestOldVersion(tt.packageName, tt.packageVersion, tt.prTitle); got != tt.want {
				t.Errorf("isPullRequestOldVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}
