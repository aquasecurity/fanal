package yaml

import (
	"io/ioutil"
	"testing"

	"github.com/open-policy-agent/conftest/parser/yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

func Test_yamlConfigAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name        string
		policyPaths []string
		inputFile   string
		want        *analyzer.AnalysisResult
		wantErr     string
	}{
		{
			name:        "happy path",
			policyPaths: []string{"../testdata/non.rego"},
			inputFile:   "testdata/deployment.yaml",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					types.Misconfiguration{
						FileType:  types.YAML,
						FilePath:  "testdata/deployment.yaml",
						Namespace: "testdata",
						Successes: 2,
						Warnings:  nil,
						Failures:  nil,
					},
				},
			},
		},
		{
			name:        "deny",
			policyPaths: []string{"../testdata/deny.rego"},
			inputFile:   "testdata/deployment.yaml",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					types.Misconfiguration{
						FileType:  types.YAML,
						FilePath:  "testdata/deployment.yaml",
						Namespace: "testdata",
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
			name:        "violation",
			policyPaths: []string{"../testdata/violation.rego"},
			inputFile:   "testdata/deployment.yaml",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					types.Misconfiguration{
						FileType:  types.YAML,
						FilePath:  "testdata/deployment.yaml",
						Namespace: "testdata",
						Successes: 1,
						Warnings:  nil,
						Failures: []types.MisconfResult{
							types.MisconfResult{
								Type:     "",
								ID:       "UNKNOWN",
								Message:  `violation: too many replicas: 3`,
								Severity: "UNKNOWN",
							},
						},
					},
				},
			},
		},
		{
			name:        "warn",
			policyPaths: []string{"../testdata/warn.rego"},
			inputFile:   "testdata/deployment.yaml",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					types.Misconfiguration{
						FileType:  types.YAML,
						FilePath:  "testdata/deployment.yaml",
						Namespace: "testdata",
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
			name:        "warn and deny",
			policyPaths: []string{"../testdata/warn.rego", "../testdata/deny.rego"},
			inputFile:   "testdata/deployment.yaml",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					types.Misconfiguration{
						FileType:  types.YAML,
						FilePath:  "testdata/deployment.yaml",
						Namespace: "testdata",
						Successes: 2,
						Warnings: []types.MisconfResult{
							types.MisconfResult{
								Type:     "Replica Settings",
								ID:       "RULE-100",
								Message:  `warn: too many replicas: 3`,
								Severity: "LOW",
							},
						},
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
			name:        "happy path using anchors",
			policyPaths: []string{"../testdata/non.rego"},
			inputFile:   "testdata/anchor.yaml",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					types.Misconfiguration{
						FileType:  types.YAML,
						FilePath:  "testdata/anchor.yaml",
						Namespace: "testdata",
						Successes: 2,
						Warnings:  nil,
						Failures:  nil,
					},
				},
			},
		},
		{
			name:        "happy path using multiple yaml",
			policyPaths: []string{"../testdata/non.rego"},
			inputFile:   "testdata/multiple.yaml",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					types.Misconfiguration{
						FileType:  types.YAML,
						FilePath:  "testdata/multiple.yaml",
						Namespace: "testdata",
						Successes: 4,
						Warnings:  nil,
						Failures:  nil,
					},
				},
			},
		},
		{
			name:        "broken YAML",
			policyPaths: []string{"../testdata/non.rego"},
			inputFile:   "testdata/broken.yaml",
			wantErr:     "unmarshal yaml",
		},
		{
			name:        "invalid circular references yaml",
			policyPaths: []string{"../testdata/non.rego"},
			inputFile:   "testdata/circular_references.yaml",
			wantErr:     "yaml: anchor 'circular' value contains itself",
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

func Test_yamlConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "yaml",
			filePath: "deployment.yaml",
			want:     true,
		},
		{
			name:     "yml",
			filePath: "deployment.yml",
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
				parser: &yaml.Parser{},
			}

			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_yamlConfigAnalyzer_Type(t *testing.T) {
	want := analyzer.TypeYaml
	a := ConfigScanner{
		parser: &yaml.Parser{},
	}
	got := a.Type()
	assert.Equal(t, want, got)
}
