package docker

import (
	"io/ioutil"
	"testing"

	"github.com/open-policy-agent/conftest/parser/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

func Test_dockerConfigAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name        string
		policyPaths []string
		inputFile   string
		want        *analyzer.AnalysisResult
		wantErr     string
	}{
		{
			name:        "happy path",
			policyPaths: []string{"../testdata/docker_non.rego"},
			inputFile:   "testdata/Dockerfile.deployment",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					types.Misconfiguration{
						FileType:  types.Dockerfile,
						FilePath:  "testdata/Dockerfile.deployment",
						Namespace: "testdata",
						Successes: 1,
						Warnings:  nil,
						Failures:  nil,
					},
				},
			},
		},
		{
			name:        "happy path with multi-stage",
			policyPaths: []string{"../testdata/docker_non.rego"},
			inputFile:   "testdata/Dockerfile.multistage",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					types.Misconfiguration{
						FileType:  types.Dockerfile,
						FilePath:  "testdata/Dockerfile.multistage",
						Namespace: "testdata",
						Successes: 1,
						Warnings:  nil,
						Failures:  nil,
					},
				},
			},
		},
		{
			name:        "deny",
			policyPaths: []string{"../testdata/docker_deny.rego"},
			inputFile:   "testdata/Dockerfile.deployment",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					types.Misconfiguration{
						FileType:  types.Dockerfile,
						FilePath:  "testdata/Dockerfile.deployment",
						Namespace: "testdata",
						Successes: 0,
						Warnings:  nil,
						Failures: []types.MisconfResult{
							types.MisconfResult{
								Type:     "Docker Security Check",
								ID:       "RULE-100",
								Message:  `deny: image found ["foo"]`,
								Severity: "HIGH",
							},
						},
					},
				},
			},
		},
		{
			name:        "violation",
			policyPaths: []string{"../testdata/docker_violation.rego"},
			inputFile:   "testdata/Dockerfile.deployment",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					types.Misconfiguration{
						FileType:  types.Dockerfile,
						FilePath:  "testdata/Dockerfile.deployment",
						Namespace: "testdata",
						Successes: 0,
						Warnings:  nil,
						Failures: []types.MisconfResult{
							types.MisconfResult{
								Type:     "",
								ID:       "UNKNOWN",
								Message:  `violation: image found ["foo"]`,
								Severity: "UNKNOWN",
							},
						},
					},
				},
			},
		},
		{
			name:        "warn",
			policyPaths: []string{"../testdata/docker_warn.rego"},
			inputFile:   "testdata/Dockerfile.deployment",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					types.Misconfiguration{
						FileType:  types.Dockerfile,
						FilePath:  "testdata/Dockerfile.deployment",
						Namespace: "testdata",
						Successes: 0,
						Warnings: []types.MisconfResult{
							types.MisconfResult{
								Type:     "",
								ID:       "UNKNOWN",
								Message:  `warn: image found ["foo"]`,
								Severity: "UNKNOWN",
							},
						},
						Failures: nil,
					},
				},
			},
		},
		{
			name:        "warn and deny",
			policyPaths: []string{"../testdata/docker_multi.rego"},
			inputFile:   "testdata/Dockerfile.deployment",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					types.Misconfiguration{
						FileType:  types.Dockerfile,
						FilePath:  "testdata/Dockerfile.deployment",
						Namespace: "testdata",
						Successes: 0,
						Warnings: []types.MisconfResult{
							types.MisconfResult{
								Type:     "Docker Security Check",
								ID:       "RULE-10",
								Message:  `warn: command ["echo hello"] contains banned: ["echo"]`,
								Severity: "LOW",
							},
						},
						Failures: []types.MisconfResult{
							types.MisconfResult{
								Type:     "Docker Security Check",
								ID:       "RULE-100",
								Message:  `deny: image found ["foo"]`,
								Severity: "HIGH",
							},
						},
					},
				},
			},
		},
		{
			name:        "broken Docker: env no value",
			policyPaths: []string{"../testdata/docker_non.rego"},
			inputFile:   "testdata/Dockerfile.broken",
			wantErr:     "parse dockerfile: ENV must have two arguments",
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

func Test_dockerConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := ConfigScanner{
				parser: &docker.Parser{},
			}

			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_dockerConfigAnalyzer_Type(t *testing.T) {
	want := analyzer.TypeDockerfile
	a := ConfigScanner{
		parser: &docker.Parser{},
	}
	got := a.Type()
	assert.Equal(t, want, got)
}
