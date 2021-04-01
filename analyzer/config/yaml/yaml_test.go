package yaml_test

import (
	"io/ioutil"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config/yaml"
	"github.com/aquasecurity/fanal/types"
)

func Test_yamlConfigAnalyzer_Analyze(t *testing.T) {
	type args struct {
		namespaces  []string
		policyPaths []string
	}
	tests := []struct {
		name      string
		args      args
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name: "happy path",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/kubernetes.rego"},
			},
			inputFile: "testdata/deployment.yaml",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType: types.Kubernetes,
						FilePath: "testdata/deployment.yaml",
						Successes: []types.MisconfResult{
							{
								Namespace: "main.kubernetes.xyz_100",
								MisconfMetadata: types.MisconfMetadata{
									ID:       "XYZ-100",
									Type:     "Kubernetes Security Check",
									Title:    "Bad Kubernetes Replicas",
									Severity: "HIGH",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "deny",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/kubernetes.rego"},
			},
			inputFile: "testdata/deployment_deny.yaml",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType: types.Kubernetes,
						FilePath: "testdata/deployment_deny.yaml",
						Failures: []types.MisconfResult{
							{
								Namespace: "main.kubernetes.xyz_100",
								Message:   "too many replicas: 4",
								MisconfMetadata: types.MisconfMetadata{
									ID:       "XYZ-100",
									Type:     "Kubernetes Security Check",
									Title:    "Bad Kubernetes Replicas",
									Severity: "HIGH",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path using anchors",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"testdata/deny.rego"},
			},
			inputFile: "testdata/anchor.yaml",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType: types.YAML,
						FilePath: "testdata/anchor.yaml",
						Failures: []types.MisconfResult{
							{
								Namespace: "main.yaml.xyz_123",
								Message:   "bad",
								MisconfMetadata: types.MisconfMetadata{
									ID:       "XYZ-123",
									Type:     "YAML Security Check",
									Title:    "Bad YAML",
									Severity: "CRITICAL",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple yaml",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/kubernetes.rego"},
			},
			inputFile: "testdata/multiple.yaml",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType: types.Kubernetes,
						FilePath: "testdata/multiple.yaml",
						Successes: []types.MisconfResult{
							{
								Namespace: "main.kubernetes.xyz_100",
								MisconfMetadata: types.MisconfMetadata{
									ID:       "XYZ-100",
									Type:     "Kubernetes Security Check",
									Title:    "Bad Kubernetes Replicas",
									Severity: "HIGH",
								},
							},
						},
						Failures: []types.MisconfResult{
							{
								Namespace: "main.kubernetes.xyz_100",
								Message:   "too many replicas: 4",
								MisconfMetadata: types.MisconfMetadata{
									ID:       "XYZ-100",
									Type:     "Kubernetes Security Check",
									Title:    "Bad Kubernetes Replicas",
									Severity: "HIGH",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "broken YAML",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/kubernetes.rego"},
			},
			inputFile: "testdata/broken.yaml",
			wantErr:   "unmarshal yaml",
		},
		{
			name: "invalid circular references yaml",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/kubernetes.rego"},
			},
			inputFile: "testdata/circular_references.yaml",
			wantErr:   "yaml: anchor 'circular' value contains itself",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a, err := yaml.NewConfigScanner(nil, tt.args.namespaces, tt.args.policyPaths, nil)
			require.NoError(t, err)

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
		name        string
		filePattern *regexp.Regexp
		filePath    string
		want        bool
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
		{
			name:        "file pattern",
			filePattern: regexp.MustCompile(`foo*`),
			filePath:    "foo_file",
			want:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := yaml.NewConfigScanner(tt.filePattern, nil, []string{"../testdata"}, nil)
			require.NoError(t, err)

			got := s.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_yamlConfigAnalyzer_Type(t *testing.T) {
	s, err := yaml.NewConfigScanner(nil, nil, []string{"../testdata"}, nil)
	require.NoError(t, err)

	want := analyzer.TypeYaml
	got := s.Type()
	assert.Equal(t, want, got)
}
