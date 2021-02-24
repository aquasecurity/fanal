package hcl2

import (
	"io/ioutil"
	"testing"

	"github.com/open-policy-agent/conftest/parser/hcl2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/types"
)

func Test_hcl2ConfigAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/deployment.hcl",
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     config.HCL2,
						FilePath: "testdata/deployment.hcl",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": map[string]interface{}{
								"name": "hello-kubernetes",
							},
							"spec": map[string]interface{}{
								"replicas": float64(3),
							},
						},
					},
				},
			},
		},
		{
			name:      "deprecated HCL2",
			inputFile: "testdata/deprecated.hcl",
			wantErr:   "unable to parse HCL2",
		},
		{
			name:      "broken HCL2",
			inputFile: "testdata/broken.hcl",
			wantErr:   "unable to parse HCL2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a := hcl2ConfigAnalyzer{
				parser: &hcl2.Parser{},
			}

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

func Test_hcl2ConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "hcl",
			filePath: "deployment.hcl",
			want:     true,
		},
		{
			name:     "json",
			filePath: "deployment.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := hcl2ConfigAnalyzer{
				parser: &hcl2.Parser{},
			}

			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
