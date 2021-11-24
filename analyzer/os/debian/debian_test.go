package debian

import (
	"context"
	"io/ioutil"
	"testing"

	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_debianOSAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path with debian 9",
			inputFile: "testdata/debian_9/etc/debian_version",
			want: &analyzer.AnalysisResult{
				OS: &types.OS{
					Family: aos.Debian,
					Name:   "9.8",
				},
			},
		},
		{
			name:      "happy path with debian sid",
			inputFile: "testdata/debian_sid/etc/debian_version",
			want: &analyzer.AnalysisResult{
				OS: &types.OS{
					Family: aos.Debian,
					Name:   "buster/sid",
				},
			},
		},
		{
			name:      "sad path with empty file",
			inputFile: "testdata/empty",
			wantErr:   "debian: unable to analyze OS information",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := debianOSAnalyzer{}
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)
			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisTarget{
				FilePath: "etc/debian_version",
				Content:  b,
			})
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
