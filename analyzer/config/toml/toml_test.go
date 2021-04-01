package toml_test

import (
	"io/ioutil"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config/toml"
	"github.com/aquasecurity/fanal/types"
)

func Test_tomlConfigAnalyzer_Analyze(t *testing.T) {
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
			inputFile: "testdata/deployment.toml",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType: types.Kubernetes,
						FilePath: "testdata/deployment.toml",
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
			inputFile: "testdata/deployment_deny.toml",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType: types.Kubernetes,
						FilePath: "testdata/deployment_deny.toml",
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
			name: "broken TOML",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/kubernetes.rego"},
			},
			inputFile: "testdata/broken.toml",
			wantErr:   "unmarshal toml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a, err := toml.NewConfigScanner(nil, tt.args.namespaces, tt.args.policyPaths, nil)
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

func Test_tomlConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name        string
		filePattern *regexp.Regexp
		filePath    string
		want        bool
	}{
		{
			name:     "toml",
			filePath: "deployment.toml",
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
			s, err := toml.NewConfigScanner(tt.filePattern, nil, []string{"../testdata"}, nil)
			require.NoError(t, err)

			got := s.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_tomlConfigAnalyzer_Type(t *testing.T) {
	s, err := toml.NewConfigScanner(nil, nil, []string{"../testdata"}, nil)
	require.NoError(t, err)

	want := analyzer.TypeTOML
	got := s.Type()
	assert.Equal(t, want, got)
}
