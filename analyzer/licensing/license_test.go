package licensing

import (
	"context"
	"os"
	"testing"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AnalyzeLicenses(t *testing.T) {
	tests := []struct {
		name                 string
		configPath           string
		filePath             string
		expectedHandlerFiles int
	}{
		{
			name:                 "Licensed C file",
			filePath:             "testdata/licensed.c",
			expectedHandlerFiles: 1,
		},
		{
			name:                 "Another Licensed C file",
			filePath:             "testdata/another_licensed.c",
			configPath:           "testdata/configFiles/showEverything.yaml",
			expectedHandlerFiles: 1,
		},
		{
			name:                 "Creative Commons License file",
			filePath:             "testdata/LICENSE_cc",
			expectedHandlerFiles: 1,
		},
		{
			name:                 "Unlicensed C file",
			filePath:             "testdata/unlicensed.c",
			expectedHandlerFiles: 0,
		},
		{
			name:                 "Licensed C with config ignoring license",
			filePath:             "testdata/licensed.c",
			configPath:           "testdata/configFiles/ignoredLicenses.yaml",
			expectedHandlerFiles: 0,
		},
		{
			name:                 "Licensed C with config having high confidence threshold",
			filePath:             "testdata/licensed.c",
			configPath:           "testdata/configFiles/highConfidenceThreshold.yaml",
			expectedHandlerFiles: 0,
		},
		{
			name:                 "Non human readable binary file",
			filePath:             "testdata/binaryfile",
			expectedHandlerFiles: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newLicenseScanner(tt.configPath)
			require.NoError(t, err)
			content, err := os.Open(tt.filePath)
			require.NoError(t, err)
			fi, err := content.Stat()
			require.NoError(t, err)

			got, err := a.Analyze(context.TODO(), analyzer.AnalysisInput{
				FilePath: tt.filePath,
				Content:  content,
				Info:     fi,
			})
			require.NoError(t, err)

			if tt.expectedHandlerFiles > 0 {
				assert.Len(t, got.Files, tt.expectedHandlerFiles)
			} else {
				assert.Nil(t, got)
			}
		})
	}

}

func Test_LicenseAnalysisRequired(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "C file with license",
			filePath: "testdata/licensed.c",
			want:     true,
		},
		{
			name:     "C file without license",
			filePath: "testdata/unlicensed.c",
			want:     true,
		},
		{
			name:     "Creative Commons License file",
			filePath: "testdata/LICENSE_cc",
			want:     true,
		},
		{
			name:     "Unreadable file",
			filePath: "testdata/binaryfile",
			want:     true,
		},
		{
			name:     "Image file",
			filePath: "testdata/picture.png",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newLicenseScanner("")
			require.NoError(t, err)

			fi, err := os.Stat(tt.filePath)
			require.NoError(t, err)

			got := a.Required(tt.filePath, fi)
			assert.Equal(t, tt.want, got)
		})
	}
}
