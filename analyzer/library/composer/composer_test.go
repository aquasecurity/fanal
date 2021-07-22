package composer

import (
	"io/ioutil"
	"testing"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_composer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/composer.lock",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Composer,
						FilePath: "testdata/composer.lock",
						Libraries: []types.LibraryInfo{
							{Library: godeptypes.Library{Name: "pear/log", Version: "1.13.1", License: ""}},
							{Library: godeptypes.Library{Name: "pear/pear_exception", Version: "v1.0.0", License: ""}},
						},
					},
				},
			},
		},
		{
			name:      "happy path - wordpress",
			inputFile: "testdata/wp-includes/version.php",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Composer,
						FilePath: "testdata/wp-includes/version.php",
						Libraries: []types.LibraryInfo{
							{Library: godeptypes.Library{Name: "wordpress", Version: "4.9.4-alpha"}},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a := composerLibraryAnalyzer{}
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
