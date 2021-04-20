package yaml_test

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/config/parser/yaml"
)

func Test_yamlParser_Parse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      interface{}
		wantErr   string
	}{
		{
			name: "happy path",
			inputFile: "testdata/deployment.yaml",
			want: map[string]interface{}{
				"apiVersion":"apps/v1",
				"kind":"Deployment",
				"metadata":map[string]interface{}{
					"name":"hello-kubernetes",
				},
				"spec":map[string]interface {}{
					"replicas":4,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)
			p := yaml.Parser{}
			got, err := p.Parse(b)
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
