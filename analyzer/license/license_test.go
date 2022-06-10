package license

import (
	"context"
	"os"
	"testing"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AnalyzeLicenses(t *testing.T) {
	tests := []struct {
		name       string
		configPath string
		filePath   string
		want       *analyzer.AnalysisResult
	}{
		{
			name:     "Licensed C file",
			filePath: "testdata/licensed.c",
			want: &analyzer.AnalysisResult{
				Licenses: []types.License{
					{
						FilePath: "testdata/licensed.c",
						Findings: []types.LicenseFinding{
							{
								Name:       "BSD-3-Clause",
								MatchType:  "License",
								Variant:    "license.txt",
								Confidence: 0.9812206572769953,
								StartLine:  5,
								EndLine:    27,
							},
						},
					},
				},
			},
		},
		{
			name:     "MIT License file",
			filePath: "testdata/LICENSE",
			want: &analyzer.AnalysisResult{
				Licenses: []types.License{
					{
						FilePath: "testdata/LICENSE",
						Findings: []types.LicenseFinding{
							{
								Name:       "MIT",
								MatchType:  "License",
								Variant:    "license.txt",
								Confidence: 1,
								StartLine:  5,
								EndLine:    21,
							},
						},
					},
				},
			},
		},
		{
			name:     "Unlicensed C ",
			filePath: "testdata/unlicensed.c",
			want:     nil,
		},
		{
			name:       "Licensed C with config ignoring license",
			filePath:   "testdata/licensed.c",
			configPath: "testdata/configFiles/ignoredLicenses.yaml",
			want:       nil,
		},
		{
			name:       "Licensed C with config having high confidence threshold",
			filePath:   "testdata/licensed.c",
			configPath: "testdata/configFiles/highConfidenceThreshold.yaml",
			want:       nil,
		},
		{
			name:     "Non human readable binary file",
			filePath: "testdata/binaryfile",
			want:     nil,
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
			assert.Equal(t, tt.want, got)
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
			name:     "MIT License file",
			filePath: "testdata/LICENSE",
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
