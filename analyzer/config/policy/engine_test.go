package policy_test

import (
	"context"
	"testing"

	"github.com/aquasecurity/fanal/analyzer/config/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/types"
)

func TestEngine_Check(t *testing.T) {
	type args struct {
		configType string
		filePath   string
		config     interface{}
		namespaces []string
	}
	tests := []struct {
		name        string
		policyPaths []string
		dataPaths   []string
		args        args
		want        types.Misconfiguration
		wantErr     string
	}{
		{
			name:        "happy path",
			policyPaths: []string{"testdata/happy"},
			args: args{
				configType: types.Kubernetes,
				filePath:   "deployment.yaml",
				config: map[string]interface{}{
					"apiVersion": "apps/v1",
					"kind":       "Deployment",
					"metadata": map[string]interface{}{
						"name": "test",
					},
				},
				namespaces: []string{"testdata", "dummy"},
			},
			want: types.Misconfiguration{
				FileType: types.Kubernetes,
				FilePath: "deployment.yaml",
				Successes: []types.MisconfResult{
					{
						Namespace: "testdata.kubernetes.xyz_200",
						MisconfMetadata: types.MisconfMetadata{
							ID:       "XYZ-200",
							Type:     "Kubernetes Security Check",
							Title:    "Bad Pod",
							Severity: "CRITICAL",
						},
					},
				},
				Failures: []types.MisconfResult{
					{
						Namespace: "testdata.kubernetes.xyz_100",
						Message:   "deny test",
						MisconfMetadata: types.MisconfMetadata{
							ID:       "XYZ-100",
							Type:     "Kubernetes Security Check",
							Title:    "Bad Deployment",
							Severity: "HIGH",
						},
					},
				},
			},
		},
		{
			name:        "sub configs",
			policyPaths: []string{"testdata/happy"},
			args: args{
				configType: types.Kubernetes,
				filePath:   "deployment.yaml",
				config: []interface{}{
					map[string]interface{}{
						"apiVersion": "apps/v1",
						"kind":       "Deployment",
						"metadata": map[string]interface{}{
							"name": "test1",
						},
					},
					map[string]interface{}{
						"apiVersion": "apps/v1",
						"kind":       "Deployment",
						"metadata": map[string]interface{}{
							"name": "test2",
						},
					},
				},
				namespaces: []string{"testdata", "dummy"},
			},
			want: types.Misconfiguration{
				FileType: types.Kubernetes,
				FilePath: "deployment.yaml",
				Successes: []types.MisconfResult{
					{
						Namespace: "testdata.kubernetes.xyz_200",
						MisconfMetadata: types.MisconfMetadata{
							ID:       "XYZ-200",
							Type:     "Kubernetes Security Check",
							Title:    "Bad Pod",
							Severity: "CRITICAL",
						},
					},
				},
				Failures: []types.MisconfResult{
					{
						Namespace: "testdata.kubernetes.xyz_100",
						Message:   "deny test1",
						MisconfMetadata: types.MisconfMetadata{
							ID:       "XYZ-100",
							Type:     "Kubernetes Security Check",
							Title:    "Bad Deployment",
							Severity: "HIGH",
						},
					},
					{
						Namespace: "testdata.kubernetes.xyz_100",
						Message:   "deny test2",
						MisconfMetadata: types.MisconfMetadata{
							ID:       "XYZ-100",
							Type:     "Kubernetes Security Check",
							Title:    "Bad Deployment",
							Severity: "HIGH",
						},
					},
				},
			},
		},
		{
			name:        "namespace exception",
			policyPaths: []string{"testdata/namespace_exception"},
			args: args{
				configType: types.Kubernetes,
				filePath:   "deployment.yaml",
				config: map[string]interface{}{
					"apiVersion": "apps/v1",
					"kind":       "Deployment",
					"metadata": map[string]interface{}{
						"name": "test",
					},
				},
				namespaces: []string{"testdata", "dummy"},
			},
			want: types.Misconfiguration{
				FileType: types.Kubernetes,
				FilePath: "deployment.yaml",
				Failures: []types.MisconfResult{
					{
						Namespace: "testdata.kubernetes.xyz_200",
						Message:   "deny 200 test",
						MisconfMetadata: types.MisconfMetadata{
							ID:       "XYZ-200",
							Type:     "Kubernetes Security Check",
							Title:    "Bad Deployment",
							Severity: "HIGH",
						},
					},
				},
				Exceptions: []types.MisconfResult{
					{
						Namespace: "testdata.kubernetes.xyz_100",
						Message:   `data.namespace.exceptions.exception[_] == "testdata.kubernetes.xyz_100"`,
					},
				},
			},
		},
		{
			name:        "rule exception",
			policyPaths: []string{"testdata/rule_exception"},
			args: args{
				configType: types.Kubernetes,
				filePath:   "deployment.yaml",
				config: map[string]interface{}{
					"apiVersion": "apps/v1",
					"kind":       "Deployment",
					"metadata": map[string]interface{}{
						"name": "test",
					},
				},
				namespaces: []string{"testdata", "dummy"},
			},
			want: types.Misconfiguration{
				FileType: types.Kubernetes,
				FilePath: "deployment.yaml",
				Failures: []types.MisconfResult{
					{
						Namespace: "testdata.kubernetes.xyz_100",
						Message:   "deny bar test",
						MisconfMetadata: types.MisconfMetadata{
							ID:       "XYZ-100",
							Type:     "Kubernetes Security Check",
							Title:    "Bad Deployment",
							Severity: "HIGH",
						},
					},
				},
				Exceptions: []types.MisconfResult{
					{
						Namespace: "testdata.kubernetes.xyz_100",
						Message:   `data.testdata.kubernetes.xyz_100.exception[_][_] == "foo"`,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := policy.Load(tt.policyPaths, tt.dataPaths)
			require.NoError(t, err)

			got, err := engine.Check(context.Background(), tt.args.configType, tt.args.filePath, tt.args.config, tt.args.namespaces)
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
