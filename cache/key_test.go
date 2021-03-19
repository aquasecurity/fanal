package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer/config"
)

func TestWithVersionSuffix(t *testing.T) {
	type args struct {
		key     string
		version string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				key:     "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				version: "111101112110013",
			},
			want: "sha256:18d64117ccf048ed38c21e98c57dbbde66b181edc1bde792256eaa931bf0f7b1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := &config.ScannerOption{
				FilePatterns: []string{":"},
			}
			got, err := CalcKey(tt.args.key, tt.args.version, opt)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
