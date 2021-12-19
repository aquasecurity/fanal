package photon

import (
	"context"
	"os"
	"testing"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/types"
)

func Test_photonOSAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path with Photon OS 3.0",
			inputFile: "testdata/photon_3/os-release",
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Photon, Name: "3.0"},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/not_photon/os-release",
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Photon, Name: "3.0"},
			},
			wantErr: "photon: unable to analyze OS information",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := photonOSAnalyzer{}
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisTarget{
				FilePath:      "etc/os-release",
				ContentReader: f,
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
