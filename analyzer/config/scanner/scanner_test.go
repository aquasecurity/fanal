package scanner

import (
	"regexp"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
			scanner := New(tt.re, nil, nil, nil)
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
		want        []types.Misconfiguration
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
			want: []types.Misconfiguration{
				{
					FileType:  "kubernetes",
					FilePath:  "deployment.yaml",
					Namespace: "testdata.kubernetes.id_100",
					Successes: 0,
					Failures: []types.MisconfResult{
						{
							Type:     "Kubernetes Check",
							ID:       "ID-100",
							Message:  "deny",
							Severity: "CRITICAL",
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
			want: []types.Misconfiguration{
				{
					FileType:  types.Kubernetes,
					FilePath:  "deployment.yaml",
					Namespace: "testdata.kubernetes.id_100",
					Successes: 0,
					Failures: []types.MisconfResult{
						{
							Type:     "Kubernetes Check",
							ID:       "ID-100",
							Message:  "deny",
							Severity: "CRITICAL",
						},
					},
				},
				{
					FileType:  types.Kubernetes,
					FilePath:  "deployment.yaml",
					Namespace: "testdata.kubernetes.id_200",
					Successes: 0,
					Failures: []types.MisconfResult{
						{
							Type:     "Kubernetes Check",
							ID:       "ID-200",
							Message:  "deny",
							Severity: "HIGH",
						},
					},
				},
			},
		},
		{
			name:       "policy load error/not supplied",
			configType: types.Kubernetes,
			wantErr:    "policy load error",
		},
		{
			name:        "policy load error/no policy found",
			policyPaths: []string{"testdata/noexist.rego"},
			configType:  types.Kubernetes,
			wantErr:     "policy load error",
		},
		{
			name:        "policy load error/invalid",
			policyPaths: []string{"testdata/invalid"},
			configType:  types.Kubernetes,
			wantErr:     "policy load error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := New(nil, tt.namespaces, tt.policyPaths, tt.dataPaths)
			got, err := scanner.ScanConfig(tt.configType, "deployment.yaml", tt.content)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, got)
				return
			}

			sort.Slice(got, func(i, j int) bool {
				return got[i].Namespace < got[j].Namespace
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
