package docker_test

import (
	"io/ioutil"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config/docker"
	"github.com/aquasecurity/fanal/types"
)

func Test_dockerConfigAnalyzer_Analyze(t *testing.T) {
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
				policyPaths: []string{"../testdata/docker_non.rego"},
			},
			inputFile: "testdata/Dockerfile.deployment",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType: types.Dockerfile,
						FilePath: "testdata/Dockerfile.deployment",
						Successes: []types.MisconfResult{
							{
								Namespace: "main.dockerfile",
								MisconfMetadata: types.MisconfMetadata{
									ID:       "XYZ-100",
									Type:     "Docker Security Check",
									Title:    "Bad Dockerfile",
									Severity: "HIGH",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path with multi-stage",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/docker_non.rego"},
			},
			inputFile: "testdata/Dockerfile.multistage",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType: types.Dockerfile,
						FilePath: "testdata/Dockerfile.multistage",
						Successes: []types.MisconfResult{
							{
								Namespace: "main.dockerfile",
								MisconfMetadata: types.MisconfMetadata{
									ID:       "XYZ-100",
									Type:     "Docker Security Check",
									Title:    "Bad Dockerfile",
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
				namespaces:  []string{"main", "users"},
				policyPaths: []string{"../testdata/docker_deny.rego"},
			},
			inputFile: "testdata/Dockerfile.deployment",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType: types.Dockerfile,
						FilePath: "testdata/Dockerfile.deployment",
						Failures: []types.MisconfResult{
							{
								Namespace: "users.dockerfile.xyz_100",
								Message:   `deny: image found ["foo"]`,
								MisconfMetadata: types.MisconfMetadata{
									ID:       "XYZ-100",
									Type:     "Docker Security Check",
									Title:    "Bad Dockerfile",
									Severity: "HIGH",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "violation",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/docker_violation.rego"},
			},
			inputFile: "testdata/Dockerfile.deployment",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType: types.Dockerfile,
						FilePath: "testdata/Dockerfile.deployment",
						Warnings: nil,
						Failures: []types.MisconfResult{
							{
								Namespace: "main.dockerfile.id_100",
								Message:   `violation: image found ["foo"]`,
								MisconfMetadata: types.MisconfMetadata{
									Type:     "N/A",
									ID:       "N/A",
									Title:    "N/A",
									Severity: "UNKNOWN",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "warn",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/docker_warn.rego"},
			},
			inputFile: "testdata/Dockerfile.deployment",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType: types.Dockerfile,
						FilePath: "testdata/Dockerfile.deployment",
						Warnings: []types.MisconfResult{
							{
								Namespace: "main.dockerfile.xyz_100",
								Message:   `warn: image found ["foo"]`,
								MisconfMetadata: types.MisconfMetadata{
									Type:     "N/A",
									ID:       "XYZ-100",
									Title:    "Bad Dockerfile",
									Severity: "UNKNOWN",
								},
							},
						},
						Failures: nil,
					},
				},
			},
		},
		{
			name: "warn and deny",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/docker_multi.rego"},
			},
			inputFile: "testdata/Dockerfile.deployment",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType: types.Dockerfile,
						FilePath: "testdata/Dockerfile.deployment",
						Warnings: []types.MisconfResult{
							{
								Namespace: "main.dockerfile",
								Message:   `warn: command ["echo hello"] contains banned: ["echo"]`,
								MisconfMetadata: types.MisconfMetadata{
									Type:     "N/A",
									ID:       "N/A",
									Title:    "N/A",
									Severity: "UNKNOWN",
								},
							},
						},
						Failures: []types.MisconfResult{
							{
								Namespace: "main.dockerfile",
								Message:   `deny: image found ["foo"]`,
								MisconfMetadata: types.MisconfMetadata{
									Type:     "N/A",
									ID:       "N/A",
									Title:    "N/A",
									Severity: "UNKNOWN",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "broken Docker: env no value",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"../testdata/docker_non.rego"},
			},
			inputFile: "testdata/Dockerfile.broken",
			wantErr:   "parse dockerfile: ENV must have two arguments",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a, err := docker.NewConfigScanner(nil, tt.args.namespaces, tt.args.policyPaths, nil)
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

func Test_dockerConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name        string
		filePattern *regexp.Regexp
		filePath    string
		want        bool
	}{
		{
			name:     "dockerfile",
			filePath: "dockerfile",
			want:     true,
		},
		{
			name:     "Dockerfile",
			filePath: "Dockerfile",
			want:     true,
		},
		{
			name:     "Dockerfile with ext",
			filePath: "Dockerfile.build",
			want:     true,
		},
		{
			name:     "dockerfile as ext",
			filePath: "build.dockerfile",
			want:     true,
		},
		{
			name:     "Dockerfile in dir",
			filePath: "docker/Dockerfile",
			want:     true,
		},
		{
			name:     "Dockerfile as prefix",
			filePath: "Dockerfilebuild",
			want:     false,
		},
		{
			name:     "Dockerfile as suffix",
			filePath: "buildDockerfile",
			want:     false,
		},
		{
			name:     "Dockerfile as prefix with ext",
			filePath: "Dockerfilebuild.sh",
			want:     false,
		},
		{
			name:     "Dockerfile as suffix with ext",
			filePath: "buildDockerfile.sh",
			want:     false,
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
			s, err := docker.NewConfigScanner(tt.filePattern, nil, []string{"../testdata"}, nil)
			require.NoError(t, err)

			got := s.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_dockerConfigAnalyzer_Type(t *testing.T) {
	s, err := docker.NewConfigScanner(nil, nil, []string{"../testdata"}, nil)
	require.NoError(t, err)

	want := analyzer.TypeDockerfile
	got := s.Type()
	assert.Equal(t, want, got)
}
