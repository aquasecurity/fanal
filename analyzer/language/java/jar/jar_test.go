package jar

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func Test_javaLibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/test.war",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Jar,
						FilePath: "testdata/test.war",
						Libraries: []types.LibraryInfo{
							{Library: godeptypes.Library{Name: "org.glassfish:javax.el", Version: "3.0.0"}},
							{Library: godeptypes.Library{Name: "com.fasterxml.jackson.core:jackson-databind", Version: "2.9.10.6"}},
							{Library: godeptypes.Library{Name: "com.fasterxml.jackson.core:jackson-annotations", Version: "2.9.10"}},
							{Library: godeptypes.Library{Name: "com.fasterxml.jackson.core:jackson-core", Version: "2.9.10"}},
							{Library: godeptypes.Library{Name: "org.slf4j:slf4j-api", Version: "1.7.30"}},
							{Library: godeptypes.Library{Name: "com.cronutils:cron-utils", Version: "9.1.2"}},
							{Library: godeptypes.Library{Name: "org.apache.commons:commons-lang3", Version: "3.11"}},
							{Library: godeptypes.Library{Name: "com.example:web-app", Version: "1.0-SNAPSHOT"}},
						},
					},
				},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/test.txt",
			wantErr:   "not a valid zip file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a := javaLibraryAnalyzer{}
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

func Test_javaLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "war",
			filePath: "test/test.war",
			want:     true,
		},
		{
			name:     "jar",
			filePath: "test.jar",
			want:     true,
		},
		{
			name:     "ear",
			filePath: "a/b/c/d/test.ear",
			want:     true,
		},
		{
			name:     "capital jar",
			filePath: "a/b/c/d/test.JAR",
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
			a := javaLibraryAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
