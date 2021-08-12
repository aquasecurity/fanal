package egg

import (
	"os"
	"testing"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_eggAnalyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy_path.egg-info/PKG-INFO",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Egg,
						FilePath: "testdata/happy_path.egg-info/PKG-INFO",
						Libraries: []types.LibraryInfo{
							{
								Library: godeptypes.Library{
									Name:    "distlib",
									Version: "0.3.1",
									License: "Python license",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "no-license",
			inputFile: "testdata/no_license.egg-info/PKG-INFO",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Egg,
						FilePath: "testdata/no_license.egg-info/PKG-INFO",
						Libraries: []types.LibraryInfo{
							{
								Library: godeptypes.Library{
									Name:    "setuptools",
									Version: "51.3.3",
									License: "",
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := os.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a := eggLibraryAnalyzer{}
			got, err := a.Analyze(analyzer.AnalysisTarget{
				FilePath: tt.inputFile,
				Content:  b,
			})

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

}

func Test_eggRequired(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy",
			filePath: "python3.8/site-packages/wrapt-1.12.1.egg-info/PKG-INFO",
			want:     true,
		},
		{
			name:     "sad",
			filePath: "random/PKG-INFO",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := eggLibraryAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
