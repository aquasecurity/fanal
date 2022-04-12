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
				OS: &types.OS{Family: aos.Alpine, Name: "3.15.4", Priority: 2},
			},
		},
		{
			name: "happy path. 'etc/apk/repositories' contains 1 line with v* version",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content:  strings.NewReader("https://dl-cdn.alpinelinux.org/alpine/v3.15/main"),
			},
			wantResult: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Alpine, Name: "3.15", Priority: 1},
			},
		},
		{
			name: "happy path. 'etc/apk/repositories' contains 1 line with edge version",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content:  strings.NewReader("https://dl-cdn.alpinelinux.org/alpine/edge/main"),
			},
			wantResult: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Alpine, Name: "edge", Priority: 1},
			},
		},
		{
			name: "happy path. 'etc/apk/repositories' contains some line with v* versions",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content: strings.NewReader(`https://dl-cdn.alpinelinux.org/alpine/v3.1/main
https://dl-cdn.alpinelinux.org/alpine/v3.10/main
`),
			},
			wantResult: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Alpine, Name: "3.10", Priority: 1},
			},
		},
		{
			name: "happy path. 'etc/apk/repositories' contains some line with v* versions",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content: strings.NewReader(`https://dl-cdn.alpinelinux.org/alpine/v3.10/main
https://dl-cdn.alpinelinux.org/alpine/v3.1/main
`),
			},
			wantResult: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Alpine, Name: "3.10", Priority: 1},
			},
		},
		{
			name: "happy path. 'etc/apk/repositories' contains some line with v* and edge versions",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content: strings.NewReader(`https://dl-cdn.alpinelinux.org/alpine/edge/main
https://dl-cdn.alpinelinux.org/alpine/v3.10/main
`),
			},
			wantResult: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Alpine, Name: "edge", Priority: 1},
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
