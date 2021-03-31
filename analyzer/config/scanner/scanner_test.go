package scanner_test

import (
	"regexp"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer/config/scanner"
	"github.com/aquasecurity/fanal/types"
)

func TestScanner_Match(t *testing.T) {
	tests := []struct {
		name string
		re   *regexp.Regexp
		path string
		want bool
	}{
		{
			name: "nil pattern",
			path: "path",
		},
		{
			name: "not match",
			re:   regexp.MustCompile("p"),
			path: "dir",
		},
		{
			name: "match",
			re:   regexp.MustCompile("p"),
			path: "path",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := scanner.New(tt.re, nil, []string{"testdata/valid"}, nil)
			require.NoError(t, err)
			assert.Equal(t, tt.want, scanner.Match(tt.path))
		})
	}
}

func TestScanner_ScanConfig(t *testing.T) {
	// only does basic tests
	// check for misconfigurations in implementations
	tests := []struct {
		name        string
		policyPaths []string
		dataPaths   []string
		configType  string
		content     interface{}
		namespaces  []string
		want        types.Misconfiguration
		wantErr     string
	}{
		{
			name:        "happy path",
			policyPaths: []string{"testdata/valid/100.rego"},
			configType:  types.Kubernetes,
			content: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
			},
			namespaces: []string{"testdata"},
			want: types.Misconfiguration{
				FileType: "kubernetes",
				FilePath: "deployment.yaml",
				Failures: []types.MisconfResult{
					{
						Namespace: "testdata.kubernetes.id_100",
						Message:   "deny",
						MisconfMetadata: types.MisconfMetadata{
							Type:     "Kubernetes Security Check",
							Title:    "Bad Deployment",
							ID:       "ID-100",
							Severity: "HIGH",
						},
					},
				},
			},
		},
		{
			name:        "happy path with multiple policies",
			policyPaths: []string{"testdata/valid/"},
			configType:  types.Kubernetes,
			content: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
			},
			namespaces: []string{"testdata"},
			want: types.Misconfiguration{
				FileType: types.Kubernetes,
				FilePath: "deployment.yaml",
				Failures: []types.MisconfResult{
					{
						Namespace: "testdata.kubernetes.id_100",
						Message:   "deny",
						MisconfMetadata: types.MisconfMetadata{
							Type:     "Kubernetes Security Check",
							Title:    "Bad Deployment",
							ID:       "ID-100",
							Severity: "HIGH",
						},
					},
					{
						Namespace: "testdata.kubernetes.id_200",
						Message:   "deny",
						MisconfMetadata: types.MisconfMetadata{
							Type:     "Kubernetes Security Check",
							Title:    "Bad Deployment",
							ID:       "ID-200",
							Severity: "CRITICAL",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := scanner.New(nil, tt.namespaces, tt.policyPaths, tt.dataPaths)
			require.NoError(t, err)

			got, err := s.ScanConfig(tt.configType, "deployment.yaml", tt.content)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, got)
				return
			}

			sort.Slice(got.Failures, func(i, j int) bool {
				return got.Failures[i].Namespace < got.Failures[j].Namespace
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
