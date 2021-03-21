package scanner

import (
	"regexp"
	"testing"

	"github.com/open-policy-agent/conftest/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			scanner := NewScanner(tt.re, nil, nil)
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
		fileType    string // NOTE might want to make fanal/types and conftest/parser equal
		fileName    string
		wantErr     string
	}{
		{
			name:        "happy path",
			policyPaths: []string{"testdata/valid.rego"},
			fileType:    parser.YAML,
			fileName:    "testdata/deployment.yaml",
		},
		{
			name:     "policy load error/not supplied",
			fileType: parser.YAML,
			fileName: "testdata/deployment.yaml",
			wantErr:  "policy load error",
		},
		{
			name:        "policy load error/no policy found",
			policyPaths: []string{"testdata/noexist.rego"},
			fileType:    parser.YAML,
			fileName:    "testdata/deployment.yaml",
			wantErr:     "policy load error",
		},
		{
			name:        "policy load error/invalid",
			policyPaths: []string{"testdata/invalid.rego"},
			fileType:    parser.YAML,
			fileName:    "testdata/deployment.yaml",
			wantErr:     "policy load error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewScanner(nil, tt.policyPaths, tt.dataPaths)
			content, err := parser.ParseConfigurationsAs([]string{tt.fileName}, tt.fileType)
			require.NoError(t, err)

			got, err := scanner.ScanConfig(tt.fileType, tt.fileName, content)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, got)
				return
			}
			assert.NotNil(t, got)
		})
	}
}
