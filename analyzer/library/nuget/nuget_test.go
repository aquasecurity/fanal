package nuget

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func Test_nugetibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path config file",
			inputFile: "testdata/packages.config",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.NuGetConfig,
						FilePath: "testdata/packages.config",
						Libraries: []types.LibraryInfo{
							{Library: godeptypes.Library{Name: "Microsoft.AspNet.WebApi", Version: "5.2.2", License: ""}},
							{Library: godeptypes.Library{Name: "Newtonsoft.Json", Version: "6.0.4", License: ""}},
						},
					},
				},
			},
		},
		{
			name:      "happy path lock file",
			inputFile: "testdata/packages.lock.json",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.NuGetLock,
						FilePath: "testdata/packages.lock.json",
						Libraries: []types.LibraryInfo{
							{Library: godeptypes.Library{Name: "Newtonsoft.Json", Version: "12.0.3", License: ""}},
							{Library: godeptypes.Library{Name: "NuGet.Frameworks", Version: "5.7.0", License: ""}},
						},
					},
				},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/invalid.txt",
			wantErr:   "unable to parse NuGet file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a := nugetLibraryAnalyzer{}
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

func Test_nugetLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "config",
			filePath: "test/packages.config",
			want:     true,
		},
		{
			name:     "lock",
			filePath: "test/packages.lock.json",
			want:     true,
		},
		{
			name:     "zip",
			filePath: "test.zip",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := nugetLibraryAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
