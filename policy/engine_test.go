package policy_test

import (
	"context"
	"testing"

	"github.com/aquasecurity/fanal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/types"
)

func TestLoad(t *testing.T) {
	type args struct {
		policyPaths []string
		dataPaths   []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				policyPaths: []string{"testdata/happy"},
				dataPaths:   []string{"testdata/data"},
			},
		},
		{
			name: "broken policy",
			args: args{
				policyPaths: []string{"testdata/sad/broken_rule.rego"},
				dataPaths:   []string{"testdata/data"},
			},
			wantErr: "var msg is unsafe",
		},
		{
			name: "no policies",
			args: args{
				policyPaths: []string{"testdata/data/"},
			},
			wantErr: "no policies found in [testdata/data/]",
		},
		{
			name: "non-existent policy path",
			args: args{
				policyPaths: []string{"testdata/non-existent/"},
			},
			wantErr: "no such file or directory",
		},
		{
			name: "non-existent data path",
			args: args{
				policyPaths: []string{"testdata/happy"},
				dataPaths:   []string{"testdata/non-existent/"},
			},
			wantErr: "no such file or directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := policy.Load(tt.args.policyPaths, tt.args.dataPaths)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

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
			dataPaths:   []string{"testdata/data"},
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
			dataPaths:   []string{"testdata/data"},
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
		{
			name:        "missing id and severity",
			policyPaths: []string{"testdata/sad/missing_metadata_fields.rego"},
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
						Message:   "deny test",
						MisconfMetadata: types.MisconfMetadata{
							ID:       "N/A",
							Type:     "Kubernetes Security Check",
							Title:    "Bad Deployment",
							Severity: "UNKNOWN",
						},
					},
				},
			},
		},
		{
			name:        "missing __rego_metadata__",
			policyPaths: []string{"testdata/sad/missing_metadata.rego"},
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
						Message:   "deny test",
						MisconfMetadata: types.MisconfMetadata{
							ID:       "N/A",
							Type:     "N/A",
							Title:    "N/A",
							Severity: "UNKNOWN",
						},
					},
				},
			},
		},
		{
			name:        "broken __rego_metadata__",
			policyPaths: []string{"testdata/sad/broken_metadata.rego"},
			args: args{
				configType: types.Kubernetes,
				filePath:   "deployment.yaml",
				config: map[string]interface{}{
					"apiVersion": "apps/v1",
					"kind":       "Deployment",
				},
				namespaces: []string{"testdata", "dummy"},
			},
			wantErr: "'__rego_metadata__' must be map",
		},
		{
			name:        "broken msg",
			policyPaths: []string{"testdata/sad/broken_msg.rego"},
			args: args{
				configType: types.Kubernetes,
				filePath:   "deployment.yaml",
				config: map[string]interface{}{
					"apiVersion": "apps/v1",
					"kind":       "Deployment",
				},
				namespaces: []string{"testdata", "dummy"},
			},
			wantErr: "rule missing 'msg' field",
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
