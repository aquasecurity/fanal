package licensing

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
						FilePath: "/testdata/licensed.c",
						Findings: []types.LicenseFinding{
							{
								License:                          "AGPL-3.0",
								MatchType:                        "Header",
								GoogleLicenseClassificationIndex: 2,
								GoogleLicenseClassification:      "forbidden",
								Confidence:                       1,
								StartLine:                        2,
								EndLine:                          13,
								LicenseLink:                      "https://spdx.org/licenses/AGPL-3.0.html",
							},
						},
					},
				},
			},
		},
		{
			name:       "Another Licensed C file",
			filePath:   "testdata/another_licensed.c",
			configPath: "testdata/configFiles/showEverything.yaml",
			want: &analyzer.AnalysisResult{
				Licenses: []types.License{
					{
						FilePath: "/testdata/another_licensed.c",
						Findings: []types.LicenseFinding{
							{
								License:                          "BSL-1.0",
								MatchType:                        "License",
								GoogleLicenseClassificationIndex: 5,
								GoogleLicenseClassification:      "notice",
								Confidence:                       1,
								StartLine:                        2,
								EndLine:                          6,
								LicenseLink:                      "https://spdx.org/licenses/BSL-1.0.html",
							},
						},
					},
				},
			},
		},
		{
			name:     "Creative Commons License file",
			filePath: "testdata/LICENSE_cc",
			want: &analyzer.AnalysisResult{
				Licenses: []types.License{
					{
						FilePath: "/testdata/LICENSE_cc",
						Findings: []types.LicenseFinding{
							{
								License:                          "Commons-Clause",
								MatchType:                        "License",
								GoogleLicenseClassificationIndex: 2,
								GoogleLicenseClassification:      "forbidden",
								Confidence:                       1,
								StartLine:                        1,
								EndLine:                          13,
								LicenseLink:                      "https://spdx.org/licenses/Commons-Clause.html",
							},
						},
					},
				},
			},
		},
		{
			name:     "Unlicensed C file",
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
