package secret_test

import (
	"os"
	"testing"

	"github.com/aquasecurity/fanal/analyzer/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretRequire(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "pass regular file",
			filePath: "testdata/secret.txt",
			want:     true,
		},
		{
			name:     "skip small file",
			filePath: "testdata/emptyfile",
			want:     false,
		},
		{
			name:     "skip folder",
			filePath: "testdata/node_modules/secret.txt",
			want:     false,
		},
		{
			name:     "skip file",
			filePath: "testdata/package-lock.json",
			want:     false,
		},
		{
			name:     "skip extension",
			filePath: "testdata/secret.doc",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := secret.NewSecretAnalyzer("")
			require.NoError(t, err)

			fi, err := os.Stat(tt.filePath)
			require.NoError(t, err)

			got := a.Required(tt.filePath, fi)

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
