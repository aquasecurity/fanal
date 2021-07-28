package pip

import (
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func Test_gomodAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/requirements.txt",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Pip,
						FilePath: "testdata/requirements.txt",
						Libraries: []types.LibraryInfo{
							{Library: godeptypes.Library{Name: "click", Version: "8.0.0"}},
							{Library: godeptypes.Library{Name: "Flask", Version: "2.0.0"}},
							{Library: godeptypes.Library{Name: "itsdangerous", Version: "2.0.0"}},
							{Library: godeptypes.Library{Name: "Jinja2", Version: "3.0.0"}},
							{Library: godeptypes.Library{Name: "MarkupSafe", Version: "2.0.0"}},
							{Library: godeptypes.Library{Name: "Werkzeug", Version: "2.0.0"}},
						},
					},
				},
			},
		}, {
			name:      "sad path",
			inputFile: "testdata/invalid.txt",
			want:      nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := os.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a := pipLibraryAnalyzer{}
			got, err := a.Analyze(analyzer.AnalysisTarget{
				FilePath: tt.inputFile,
				Content:  b,
			})

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			if got != nil {
				sort.Slice(got.Applications[0].Libraries, func(i, j int) bool {
					return got.Applications[0].Libraries[i].Library.Name < got.Applications[0].Libraries[j].Library.Name
				})
				sort.Slice(tt.want.Applications[0].Libraries, func(i, j int) bool {
					return tt.want.Applications[0].Libraries[i].Library.Name < tt.want.Applications[0].Libraries[j].Library.Name
				})
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_gomodAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy",
			filePath: "test/requirements.txt",
			want:     true,
		},
		{
			name:     "sad",
			filePath: "a/b/c/d/test.sum",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := pipLibraryAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
