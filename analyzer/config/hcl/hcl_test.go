package hcl_test

import (
	"io/ioutil"
	"regexp"
	"testing"

	"github.com/aquasecurity/fanal/analyzer/config/hcl"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

func Test_hclConfigAnalyzer_Analyze(t *testing.T) {
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
			name: "HCL1: happy path",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"testdata/hcl.rego"},
			},
			inputFile: "testdata/deployment.hcl1",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType: types.HCL,
						FilePath: "testdata/deployment.hcl1",
						Successes: []types.MisconfResult{
							{
								Namespace: "main.hcl.xyz_100",
								PolicyMetadata: types.PolicyMetadata{
									ID:       "XYZ-100",
									Type:     "HCL Security Check",
									Title:    "Bad HCL",
									Severity: "HIGH",
								},
							},
						},
						Warnings: nil,
						Failures: nil,
					},
				},
			},
		},
		{
			name: "HCL2: deny",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"testdata/hcl.rego"},
			},
			inputFile: "testdata/deployment.hcl2",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType: types.HCL,
						FilePath: "testdata/deployment.hcl2",
						Failures: []types.MisconfResult{
							{
								Namespace: "main.hcl.xyz_100",
								Message:   "too many replicas: 4",
								PolicyMetadata: types.PolicyMetadata{
									ID:       "XYZ-100",
									Type:     "HCL Security Check",
									Title:    "Bad HCL",
									Severity: "HIGH",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "HCL1: broken",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"testdata/hcl.rego"},
			},
			inputFile: "testdata/broken.hcl1",
			wantErr:   "unmarshal hcl",
		},
		{
			name: "HCL2: broken",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"testdata/hcl.rego"},
			},
			inputFile: "testdata/broken.hcl2",
			wantErr:   "unable to parse HCL2",
		},
		{
			name: "HCL2: deprecated",
			args: args{
				namespaces:  []string{"main"},
				policyPaths: []string{"testdata/hcl.rego"},
			},
			inputFile: "testdata/deprecated.hcl",
			want: &analyzer.AnalysisResult{
				Misconfigurations: []types.Misconfiguration{
					{
						FileType: types.HCL,
						FilePath: "testdata/deprecated.hcl",
						Successes: []types.MisconfResult{
							{
								Namespace: "main.hcl.xyz_100",
								PolicyMetadata: types.PolicyMetadata{
									ID:       "XYZ-100",
									Type:     "HCL Security Check",
									Title:    "Bad HCL",
									Severity: "HIGH",
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

			a, err := hcl.NewConfigAnalyzer(nil, tt.args.namespaces, tt.args.policyPaths, nil)
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

func Test_hclConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name        string
		filePattern *regexp.Regexp
		filePath    string
		want        bool
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
		{
			name:        "file pattern",
			filePattern: regexp.MustCompile(`foo*`),
			filePath:    "foo_file",
			want:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := hcl.NewConfigAnalyzer(tt.filePattern, nil, []string{"../testdata"}, nil)
			require.NoError(t, err)

			got := s.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
func Test_hclConfigAnalyzer_Type(t *testing.T) {
	s, err := hcl.NewConfigAnalyzer(nil, nil, []string{"../testdata"}, nil)
	require.NoError(t, err)

	want := analyzer.TypeHCL
	got := s.Type()
	assert.Equal(t, want, got)
}
