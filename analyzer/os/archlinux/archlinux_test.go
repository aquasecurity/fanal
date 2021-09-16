package archlinux

import (
	"os"
	"testing"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_archlinuxOSAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path with ArchLinux",
			inputFile: "testdata/archlinux/os-release",
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Arch, Name: "Arch Linux"},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/not_archlinux/os-release",
			wantErr:   "arch: unable to analyze OS information",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := archlinuxOSAnalyzer{}
			b, err := os.ReadFile(tt.inputFile)
			require.NoError(t, err)

			got, err := a.Analyze(analyzer.AnalysisTarget{
				FilePath: "etc/os-release",
				Content:  b,
			})
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
