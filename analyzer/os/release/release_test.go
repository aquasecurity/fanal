package release

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
)

func Test_osReleaseAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		input     analyzer.AnalysisInput
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "alpine",
			inputFile: "testdata/alpine",
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Alpine, Name: "3.15.4"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := osReleaseAnalyzer{}
			res, err := a.Analyze(context.Background(), analyzer.AnalysisInput{
				FilePath: "etc/os-release",
				Content:  f,
			})

			if tt.wantErr != "" {
				assert.Error(t, err)
				assert.Equal(t, tt.wantErr, err.Error())
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, res)
		})
	}
}
