package ubuntu

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/aquasecurity/fanal/types"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ubuntuOSAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name       string
		inputFiles []string // info about ESM is stored in different file
		want       *analyzer.AnalysisResult
		wantErr    string
	}{
		{
			name:       "happy path. Only lsb-release file received.",
			inputFiles: []string{"testdata/lsb-release"},
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: "ubuntu", Name: "18.04"},
			},
		},
		{
			name:       "happy path. Received only status.json file with esm enabled.",
			inputFiles: []string{"testdata/esm_enable_status.json"},
			want:       nil,
		},
		{
			name:       "happy path. Received only status.json file with esm disabled.",
			inputFiles: []string{"testdata/esm_enable_status.json"},
			want:       nil,
		},
		{
			name:       "happy path. Received lsb-release then status.json with esm enabled.",
			inputFiles: []string{"testdata/lsb-release", "testdata/esm_enable_status.json"},
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: "ubuntu", Name: "18.04-ESM"},
			},
		},
		{
			name:       "happy path. Received lsb-release then status.json with esm disabled.",
			inputFiles: []string{"testdata/lsb-release", "testdata/esm_disable_status.json"},
			want:       nil,
		},
		{
			name:       "happy path. Received status.json with esm enabled then lsb-release",
			inputFiles: []string{"testdata/esm_enable_status.json", "testdata/lsb-release"},
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: "ubuntu", Name: "18.04-ESM"},
			},
		},
		{
			name:       "happy path. Received status.json with esm disabled then lsb-release",
			inputFiles: []string{"testdata/esm_disable_status.json", "testdata/lsb-release"},
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: "ubuntu", Name: "18.04"},
			},
		},
		{
			name:       "sad path",
			inputFiles: []string{"testdata/invalid"},
			wantErr:    "ubuntu: unable to analyze OS information",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			savedOsVersion := osVersion
			defer func() { osVersion = savedOsVersion }()
			a := ubuntuOSAnalyzer{}
			ctx := context.Background()

			var got *analyzer.AnalysisResult
			var err error

			for _, inputFile := range tt.inputFiles {
				var f *os.File
				f, err = os.Open(inputFile)
				require.NoError(t, err)
				defer f.Close()

				got, err = a.Analyze(ctx, analyzer.AnalysisInput{
					FilePath: createFilePathFromTestFile(inputFile),
					Content:  f,
				})
			}

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func createFilePathFromTestFile(testFile string) string {
	if strings.HasSuffix(testFile, "status.json") {
		return esmConfFilePath
	} else {
		return ubuntuConfFilePath
	}
}

func Test_ubuntuOSAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path(lsb-release)",
			filePath: "etc/lsb-release",
			want:     true,
		},
		{
			name:     "happy path(status.json)",
			filePath: "var/lib/ubuntu-advantage/status.json",
			want:     true,
		},
		{
			name:     "sad path",
			filePath: "etc/invalid",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := ubuntuOSAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
