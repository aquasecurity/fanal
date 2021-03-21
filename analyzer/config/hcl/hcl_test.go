package hcl

import (
	"io/ioutil"
	"testing"

	"github.com/open-policy-agent/conftest/parser/hcl1"
	"github.com/open-policy-agent/conftest/parser/hcl2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

func Test_hclConfigAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name        string
		policyPaths []string
		inputFile   string
		want        *analyzer.AnalysisResult
		wantErr     string
	}{
		{
			name:        "HCL1: happy path",
			policyPaths: []string{"../testdata/non.rego"},
			inputFile:   "testdata/deployment.hcl1",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType:  types.HCL,
						FilePath:  "testdata/deployment.hcl1",
						Namespace: "main",
						Successes: 2,
						Warnings:  nil,
						Failures:  nil,
					},
				},
			},
		},
		{
			name:        "HCL1: deny",
			policyPaths: []string{"../testdata/deny.rego"},
			inputFile:   "testdata/deployment.hcl1",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType:  types.HCL,
						FilePath:  "testdata/deployment.hcl1",
						Namespace: "main",
						Successes: 1,
						Warnings:  nil,
						Failures: []types.MisconfResult{
							types.MisconfResult{
								Type:     "Metadata Name Settings",
								ID:       "RULE-10",
								Message:  `deny: hello-kubernetes contains banned: hello`,
								Severity: "MEDIUM",
							},
						},
					},
				},
			},
		},
		{
			name:        "HCL1: violation",
			policyPaths: []string{"../testdata/violation.rego"},
			inputFile:   "testdata/deployment.hcl1",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType:  types.HCL,
						FilePath:  "testdata/deployment.hcl1",
						Namespace: "main",
						Successes: 1,
						Warnings:  nil,
						Failures: []types.MisconfResult{
							{
								Type:     "N/A",
								ID:       "N/A",
								Message:  `violation: too many replicas: 3`,
								Severity: "UNKNOWN",
							},
						},
					},
				},
			},
		},
		{
			name:        "HCL1: warn",
			policyPaths: []string{"../testdata/warn.rego"},
			inputFile:   "testdata/deployment.hcl1",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType:  types.HCL,
						FilePath:  "testdata/deployment.hcl1",
						Namespace: "main",
						Successes: 1,
						Warnings: []types.MisconfResult{
							types.MisconfResult{
								Type:     "Replica Settings",
								ID:       "RULE-100",
								Message:  `warn: too many replicas: 3`,
								Severity: "LOW",
							},
						},
						Failures: nil,
					},
				},
			},
		},
		{
			name:        "HCL1: warn and deny",
			policyPaths: []string{"../testdata/warn.rego", "../testdata/deny.rego"},
			inputFile:   "testdata/deployment.hcl1",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType:  types.HCL,
						FilePath:  "testdata/deployment.hcl1",
						Namespace: "main",
						Successes: 2,
						Warnings: []types.MisconfResult{
							{
								Type:     "Replica Settings",
								ID:       "RULE-100",
								Message:  `warn: too many replicas: 3`,
								Severity: "LOW",
							},
						},
						Failures: []types.MisconfResult{
							{
								Type:     "Metadata Name Settings",
								ID:       "RULE-10",
								Message:  `deny: hello-kubernetes contains banned: hello`,
								Severity: "MEDIUM",
							},
						},
					},
				},
			},
		},
		{
			name:        "HCL1: broken",
			policyPaths: []string{"../testdata/non.rego"},
			inputFile:   "testdata/broken.hcl1",
			wantErr:     "unmarshal hcl",
		},
		{
			name:        "HCL2: happy path",
			policyPaths: []string{"../testdata/non.rego"},
			inputFile:   "testdata/deployment.hcl2",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType:  types.HCL,
						FilePath:  "testdata/deployment.hcl2",
						Namespace: "main",
						Successes: 2,
						Warnings:  nil,
						Failures:  nil,
					},
				},
			},
		},
		{
			name:        "HCL2: broken",
			policyPaths: []string{"../testdata/non.rego"},
			inputFile:   "testdata/broken.hcl2",
			wantErr:     "unable to parse HCL2",
		},
		{
			name:        "HCL2: deprecated",
			policyPaths: []string{"../testdata/non.rego"},
			inputFile:   "testdata/deprecated.hcl",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType:  types.HCL,
						FilePath:  "testdata/deprecated.hcl",
						Namespace: "main",
						Successes: 2,
						Warnings:  nil,
						Failures:  nil,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a := NewConfigScanner(nil, tt.policyPaths, nil)

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
			a := ConfigScanner{
				hcl1Parser: &hcl1.Parser{},
				hcl2Parser: &hcl2.Parser{},
			}

			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
func Test_hclConfigAnalyzer_Type(t *testing.T) {
	want := analyzer.TypeHCL
	a := ConfigScanner{
		hcl1Parser: &hcl1.Parser{},
		hcl2Parser: &hcl2.Parser{},
	}

	got := a.Type()
	assert.Equal(t, want, got)
}
