package license

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/fanal/license/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func Test_LicenseScanning(t *testing.T) {

	type expectedFinding struct {
		Name                string
		MatchType           string
		Variant             string
		ConfidenceThreshold float32
		StartLine           int
		EndLine             int
	}

	tests := []struct {
		name             string
		filePath         string
		expectLicense    bool
		expectedFindings []expectedFinding
		scanConfig       *config.Config
	}{
		{
			name:          "C file with AGPL-3.0",
			filePath:      "testdata/licensed.c",
			expectLicense: true,
			expectedFindings: []expectedFinding{
				{
					Name:                "AGPL-3.0",
					MatchType:           "Header",
					Variant:             "header.txt",
					ConfidenceThreshold: 0.98,
					StartLine:           2,
					EndLine:             13,
				},
			},
		},
		{
			name:             "C file with AGPL-3.0 with 100 confidence",
			filePath:         "testdata/licensed.c",
			expectLicense:    false,
			expectedFindings: []expectedFinding{},
			scanConfig: &config.Config{
				MatchConfidenceThreshold: 1.0,
			},
		},
		{
			name:          "Picture with no license",
			filePath:      "testdata/unlicensed_picture.png",
			expectLicense: false,
		},
		{
			name:             "C file with ignored AGPL-3.0",
			filePath:         "testdata/licensed.c",
			expectLicense:    false,
			expectedFindings: []expectedFinding{},
			scanConfig: &config.Config{
				IgnoredLicences: []string{
					"AGPL-3.0",
				},
			},
		},
		{
			name:          "C file with no license",
			filePath:      "testdata/unlicensed.c",
			expectLicense: false,
		},
		{
			name:          "Creative commons License file",
			filePath:      "testdata/LICENSE_creativecommons",
			expectLicense: true,
			expectedFindings: []expectedFinding{
				{
					Name:                "Commons-Clause",
					MatchType:           "License",
					Variant:             "license.txt",
					ConfidenceThreshold: 0.98,
					StartLine:           1,
					EndLine:             13,
				},
			},
		},
		{
			name:          "Apache 2 License file",
			filePath:      "testdata/LICENSE_apache2",
			expectLicense: false,
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%#v", tt.name), func(t *testing.T) {

			configPath := ""
			var err error

			if tt.scanConfig != nil {
				configPath, err = createTestConfig(t, tt.scanConfig)
				require.NoError(t, err)
			}

			scanner, err := NewScanner(configPath)
			require.NoError(t, err)

			license := scanner.Scan(tt.filePath)

			assert.NotNil(t, license)

			if tt.expectLicense {
				assert.Len(t, license.Findings, len(tt.expectedFindings))
				for i, f := range tt.expectedFindings {
					lf := license.Findings[i]
					assert.Equal(t, f.Name, lf.Name)
					assert.Equal(t, f.MatchType, lf.MatchType)
					assert.Equal(t, f.Variant, lf.Variant)
					assert.Equal(t, f.StartLine, lf.StartLine)
					assert.Equal(t, f.EndLine, lf.EndLine)
					assert.Greater(t, lf.Confidence, 0.8)
				}
			} else {
				assert.Len(t, license.Findings, 0)
			}
		})

	}
}

func createTestConfig(t *testing.T, scanConfig *config.Config) (string, error) {
	configFile := filepath.Join(t.TempDir(), "scanConfig.yaml")
	content, err := yaml.Marshal(scanConfig)
	if err != nil {
		return "", err
	}
	return configFile, ioutil.WriteFile(configFile, content, os.ModePerm)
}
