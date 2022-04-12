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

func TestAlpineOSAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name       string
		input      analyzer.AnalysisInput
		wantResult *analyzer.AnalysisResult
		wantError  string
	}{
		{
			name: "happy path. Get OS version from 'etc/alpine-release' file",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/alpine-release",
				Content:  strings.NewReader("3.15.4"),
			},
			wantResult: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Alpine, Name: "3.15.4"},
			},
		},
		{
			name: "happy path. Get OS version from 'etc/apk/repositories' file",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content:  strings.NewReader("https://dl-cdn.alpinelinux.org/alpine/v3.15/main"),
			},
			wantResult: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Alpine, Name: "3.15"},
			},
		},
		{
			name: "happy path. Get 'edge' OS version from 'etc/apk/repositories' file",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content:  strings.NewReader("https://dl-cdn.alpinelinux.org/alpine/edge/mainf6f0e0395026"),
			},
			wantResult: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Alpine, Name: "edge"},
			},
		},
		{
			name: "sad path",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content:  strings.NewReader("https://distfiles.adelielinux.org/adelie/1.0-beta4/system/"),
			},
			wantError: "alpine: unable to analyze OS information",
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
