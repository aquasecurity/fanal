package alpine

import (
	"context"
	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestAlpineReleaseOSAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name       string
		input      analyzer.AnalysisInput
		wantResult *analyzer.AnalysisResult
		wantError  string
	}{
		{
			name: "happy path",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/alpine-release",
				Content:  strings.NewReader("3.15.4"),
			},
			wantResult: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Alpine, Name: "3.15.4"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := alpineOSAnalyzer{}
			res, err := a.Analyze(context.Background(), test.input)

			if test.wantError != "" {
				assert.NotNil(t, err)
				assert.Equal(t, test.wantError, err.Error())
			} else {
				assert.Nil(t, err)
				assert.Equal(t, test.wantResult, res)
			}
		})
	}
}
