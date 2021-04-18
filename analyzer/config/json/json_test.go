package json_test

import (
	"io/ioutil"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config/json"
	"github.com/aquasecurity/fanal/types"
)

func Test_jsonConfigAnalyzer_Analyze(t *testing.T) {
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
			inputFile: "testdata/deployment.json",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType: types.Kubernetes,
						FilePath: "testdata/deployment.json",
						Successes: []types.MisconfResult{
							{
								Namespace: "main.kubernetes.xyz_100",
								PolicyMetadata: types.PolicyMetadata{
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
			inputFile: "testdata/deployment_deny.json",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType: types.Kubernetes,
						FilePath: "testdata/deployment_deny.json",
						Failures: []types.MisconfResult{
							{
								Namespace: "main.kubernetes.xyz_100",
								Message:   "too many replicas: 4",
								PolicyMetadata: types.PolicyMetadata{
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
			name: "json array",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/kubernetes.rego"},
			},
			inputFile: "testdata/array.json",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType: types.Kubernetes,
						FilePath: "testdata/array.json",
						Failures: []types.MisconfResult{
							{
								Namespace: "main.kubernetes.xyz_100",
								Message:   "too many replicas: 4",
								PolicyMetadata: types.PolicyMetadata{
									ID:       "XYZ-100",
									Type:     "Kubernetes Security Check",
									Title:    "Bad Kubernetes Replicas",
									Severity: "HIGH",
								},
							},
							{
								Namespace: "main.kubernetes.xyz_100",
								Message:   "too many replicas: 5",
								PolicyMetadata: types.PolicyMetadata{
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
			name: "broken JSON",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/kubernetes.rego"},
			},
			inputFile: "testdata/broken.json",
			wantErr:   "unmarshal json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			s, err := json.NewConfigAnalyzer(nil, tt.args.namespaces, tt.args.policyPaths, nil)
			require.NoError(t, err)

			got, err := s.Analyze(analyzer.AnalysisTarget{
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

func Test_jsonConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name        string
		filePattern *regexp.Regexp
		filePath    string
		want        bool
	}{
		{
			name:     "json",
			filePath: "deployment.json",
			want:     true,
		},
		{
			name:     "yaml",
			filePath: "deployment.yaml",
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
			s, err := json.NewConfigAnalyzer(tt.filePattern, nil, []string{"../testdata"}, nil)
			require.NoError(t, err)

			got := s.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_jsonConfigAnalyzer_Type(t *testing.T) {
	s, err := json.NewConfigAnalyzer(nil, nil, []string{"../testdata"}, nil)
	require.NoError(t, err)

	want := analyzer.TypeJSON
	got := s.Type()
	assert.Equal(t, want, got)
}
