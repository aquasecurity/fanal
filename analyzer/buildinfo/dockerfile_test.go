package buildinfo

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
)

func Test_dockerfileAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		filePath  string
		want      *analyzer.AnalysisResult
		wantErr   bool
	}{
		{
			name:      "happy path",
			inputFile: "testdata/Dockerfile",
			filePath:  "Dockerfile-ubi8-8.3-227",
			want: &analyzer.AnalysisResult{
				BuildInfo: &analyzer.BuildInfo{
					Component: "ubi8-container",
					Version:   "8.3-227",
					Arch:      "x86_64",
				},
			},
		},
		{
			name:      "missing architecture",
			inputFile: "testdata/Dockerfile.sad",
			filePath:  "Dockerfile-ubi8-8.3-227",
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a := dockerfileAnalyzer{}
			got, err := a.Analyze(tt.filePath, b)
			if tt.wantErr {
				require.NotNil(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
