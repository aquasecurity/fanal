package suse

import (
	"context"
	"os"
	"testing"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
)

func Test_suseOSAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path with openSUSE Leap 15.0",
			inputFile: "testdata/opensuse_leap_150/os-release",
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.OpenSUSELeap, Name: "15.0"},
			},
		},
		{
			name:      "happy path with openSUSE Leap Tumbleweed",
			inputFile: "testdata/opensuse_leap_tumbleweed/os-release",
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.OpenSUSETumbleweed, Name: "20191204"},
			},
		},
		{
			name:      "happy path with SLES 15.1",
			inputFile: "testdata/sles_151/os-release",
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.SLES, Name: "15.1"},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/not_suse/os-release",
			wantErr:   "suse: unable to analyze OS information",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := suseOSAnalyzer{}
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: "etc/lsb-release",
				Content:  f,
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
