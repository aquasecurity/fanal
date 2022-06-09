package external_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/external"
	_ "github.com/aquasecurity/fanal/handler/misconf"
	"github.com/aquasecurity/fanal/types"
)

func TestConfigScanner_Scan(t *testing.T) {
	type fields struct {
		policyPaths []string
		dataPaths   []string
		namespaces  []string
	}
	tests := []struct {
		name     string
		fields   fields
		inputDir string
		want     []types.Misconfiguration
	}{
		{
			name: "deny",
			fields: fields{
				policyPaths: []string{"testdata/deny"},
				namespaces:  []string{"testdata"},
			},
			inputDir: "testdata/deny",
			want: []types.Misconfiguration{
				types.Misconfiguration{
					FileType: "dockerfile",
					FilePath: "Dockerfile",
					Successes: types.MisconfResults{
						types.MisconfResult{
							Namespace: "testdata.xyz_200",
							Query:     "data.testdata.xyz_200.deny",
							Message:   "",
							PolicyMetadata: types.PolicyMetadata{
								ID:                 "XYZ-200",
								Type:               "Dockerfile Security Check",
								Title:              "Old FROM",
								Description:        "Rego module: data.testdata.xyz_200",
								Severity:           "LOW",
								RecommendedActions: "",
								References:         []string(nil),
							},
							CauseMetadata: types.CauseMetadata{
								Resource:  "",
								Provider:  "Dockerfile",
								Service:   "general",
								StartLine: 0,
								EndLine:   0,
								Code: types.Code{
									Lines: []types.Line(nil),
								},
							}, Traces: []string(nil),
						},
					}, Warnings: types.MisconfResults(nil),
					Failures:   types.MisconfResults(nil),
					Exceptions: types.MisconfResults(nil),
					Layer: types.Layer{
						Digest: "",
						DiffID: "",
					},
				},
			},
		},
		{
			name: "allow",
			fields: fields{
				policyPaths: []string{"testdata/allow"},
				namespaces:  []string{"testdata"},
			},
			inputDir: "testdata/allow",
			want: []types.Misconfiguration{
				{
					FileType: "dockerfile",
					FilePath: "Dockerfile",
					Successes: types.MisconfResults{
						{
							Namespace: "testdata.xyz_200",
							Query:     "data.testdata.xyz_200.deny",
							PolicyMetadata: types.PolicyMetadata{
								ID:          "XYZ-200",
								Type:        "Dockerfile Security Check",
								Title:       "Old FROM",
								Description: "Rego module: data.testdata.xyz_200",
								Severity:    "LOW",
							},
							CauseMetadata: types.CauseMetadata{
								Resource:  "",
								Provider:  "Dockerfile",
								Service:   "general",
								StartLine: 0,
								EndLine:   0,
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := external.NewConfigScanner(t.TempDir(),
				tt.fields.policyPaths, tt.fields.dataPaths, tt.fields.namespaces, false)
			require.NoError(t, err)

			got, err := s.Scan(tt.inputDir)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
