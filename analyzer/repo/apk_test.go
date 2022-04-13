package repo

import (
	"context"
	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestAlpineApkOSAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name       string
		input      analyzer.AnalysisInput
		wantResult *analyzer.AnalysisResult
		wantError  string
	}{
		{
			name: "happy path. Alpine",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content:  strings.NewReader("http://nl.alpinelinux.org/alpine/v3.7/main"),
			},
			wantResult: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "3.7"},
			},
		},
		{
			name: "happy path. Adelie",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content:  strings.NewReader("https://distfiles.adelielinux.org/adelie/1.0-beta4/system/"),
			},
			wantResult: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: "adelie", Release: "1.0-beta4"},
			},
		},
		{
			name: "happy path. Link has 'http' prefix",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content:  strings.NewReader("http://nl.alpinelinux.org/alpine/v3.7/main"),
			},
			wantResult: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "3.7"},
			},
		},
		{
			name: "happy path. Link has 'https' prefix",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content:  strings.NewReader("https://dl-cdn.alpinelinux.org/alpine/v3.15/main"),
			},
			wantResult: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "3.15"},
			},
		},
		{
			name: "happy path. Link has 'ftp' prefix",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content:  strings.NewReader("ftp://dl-3.alpinelinux.org/alpine/v2.6/main"),
			},
			wantResult: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "2.6"},
			},
		},
		{
			name: "happy path. 'etc/apk/repositories' contains 1 line with edge version",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content:  strings.NewReader("https://dl-cdn.alpinelinux.org/alpine/edge/main"),
			},
			wantResult: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "edge"},
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
				Repository: &types.Repository{Family: aos.Alpine, Release: "3.10"},
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
				Repository: &types.Repository{Family: aos.Alpine, Release: "3.10"},
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
				Repository: &types.Repository{Family: aos.Alpine, Release: "edge"},
			},
		},
		{
			name: "sad path",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content:  strings.NewReader("https://dl-cdn.alpinelinux.org/alpine//edge/main"),
			},
			wantError: "repo/apk: Repository file doesn't contains version number or OS family",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := apkRepoAnalyzer{}
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
