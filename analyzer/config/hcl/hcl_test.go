package hcl

import (
	"io/ioutil"
	"testing"

	"github.com/open-policy-agent/conftest/parser/hcl1"
	"github.com/open-policy-agent/conftest/parser/hcl2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/types"
)

func Test_hclConfigAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "HCL1: happy path",
			inputFile: "testdata/deployment.hcl1",
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     config.HCL1,
						FilePath: "testdata/deployment.hcl1",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": []map[string]interface{}{
								map[string]interface{}{
									"name": "hello-kubernetes",
								},
							},
							"spec": []map[string]interface{}{
								map[string]interface{}{
									"replicas": int(3),
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "HCL1: broken",
			inputFile: "testdata/broken.hcl1",
			wantErr:   "unmarshal hcl",
		},
		{
			name:      "HCL2: happy path",
			inputFile: "testdata/deployment.hcl2",
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     config.HCL2,
						FilePath: "testdata/deployment.hcl2",
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
			name:      "HCL2: broken",
			inputFile: "testdata/broken.hcl2",
			wantErr:   "unable to parse HCL2",
		},
		{
			name:      "HCL2: deprecated",
			inputFile: "testdata/deprecated.hcl",
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     config.HCL1,
						FilePath: "testdata/deprecated.hcl",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": []map[string]interface{}{
								map[string]interface{}{
									"name": "hello-kubernetes",
								},
							},
							"spec": []map[string]interface{}{
								map[string]interface{}{
									"replicas": int(3),
								},
							},
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

			a := hclConfigAnalyzer{
				hcl1Parser: &hcl1.Parser{},
				hcl2Parser: &hcl2.Parser{},
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

func Test_hclConfigAnalyzer_Required(t *testing.T) {
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
			name:     "hcl1",
			filePath: "deployment.hcl1",
			want:     true,
		},
		{
			name:     "hcl2",
			filePath: "deployment.hcl2",
			want:     true,
		},
		{
			name:     "tf",
			filePath: "deployment.tf",
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
			a := hclConfigAnalyzer{
				hcl1Parser: &hcl1.Parser{},
				hcl2Parser: &hcl2.Parser{},
			}

			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
