package dpkg

import (
	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestDpkgAnalyzer_parseCopyrightFile(t *testing.T) {
	tests := []struct {
		name              string
		copyrightFilePath string
		wantLicense       *analyzer.AnalysisResult
	}{
		{
			name:              "happy path. 'License:' pattern + licenseclassifier",
			copyrightFilePath: "testdata/copyrightFiles/usr/share/doc/zlib1g/copyright",
			wantLicense: &analyzer.AnalysisResult{
				CustomResources: []types.CustomResource{
					{
						Type:     LicenseAdder,
						FilePath: "zlib1g",
						Data:     "Zlib",
					},
				},
			},
		},
		{
			name:              "happy path. Common license",
			copyrightFilePath: "testdata/copyrightFiles/usr/share/doc/adduser/copyright",
			wantLicense: &analyzer.AnalysisResult{
				CustomResources: []types.CustomResource{
					{
						Type:     LicenseAdder,
						FilePath: "adduser",
						Data:     "GPL-2, GPL-2.0",
					},
				},
			},
		},
		{
			name:              "happy path. There are Common license, 'License:' pattern and licenseclassifier",
			copyrightFilePath: "testdata/copyrightFiles/usr/share/doc/apt/copyright",
			wantLicense: &analyzer.AnalysisResult{
				CustomResources: []types.CustomResource{
					{
						Type:     LicenseAdder,
						FilePath: "apt",
						Data:     "GPLv2+, GPL-2, GPL-2.0",
					},
				},
			},
		},
		{
			name:              "happy path. Licenses not found",
			copyrightFilePath: "testdata/copyrightFiles/usr/share/doc/tzdata/copyright",
			wantLicense: &analyzer.AnalysisResult{
				CustomResources: []types.CustomResource{
					{
						Type:     LicenseAdder,
						FilePath: "tzdata",
						Data:     "Unknown",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			f, err := os.Open(test.copyrightFilePath)
			if err != nil {
				t.Error("unable to read test file")
			}

			license, _ := parseCopyrightFile(f, test.copyrightFilePath)
			assert.Equal(t, test.wantLicense, license)
		})
	}
}

func TestDpkgAnalyzer_isLicenseFile(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path",
			filePath: "/usr/share/doc/eject/copyright",
			want:     true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, isLicenseFile(test.filePath))
		})
	}
}

func TestDpkgAnalyzer_getPkgNameFromLicenseFilePath(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		wantPkg  string
	}{
		{
			name:     "happy path",
			filePath: "/usr/share/doc/eject/copyright",
			wantPkg:  "eject",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.wantPkg, getPkgNameFromLicenseFilePath(test.filePath))
		})
	}
}
