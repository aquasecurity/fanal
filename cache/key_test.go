package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/artifact"
)

func TestCalcKey(t *testing.T) {
	type args struct {
		key              string
		analyzerVersions map[string]int
		hookVersions     map[string]int
		skipFiles        []string
		skipDirs         []string
		patterns         []string
		policy           []string
		data             []string
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
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				hookVersions: map[string]int{
					"python-pkg": 1,
				},
			},
			want: "sha256:ca3763e29fc7eb882e88288a19a945f9c8755bf091d2afa7b13e7364d8a450be",
		},
		{
			name: "with disabled analyzer",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: map[string]int{
					"alpine": 1,
					"debian": 0,
					"redhat": 2,
				},
				hookVersions: map[string]int{
					"python-pkg": 1,
				},
			},
			want: "sha256:7b70f2f498b7e61a283b6467dd5158b677fac3892549f34ea5ddac861c602b74",
		},
		{
			name: "with empty slice file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				patterns: []string{},
			},
			want: "sha256:17d6090b9a567b40432b74d8aed0a2344444dde05dd2de5e3a9a0d40dcfc2cfc",
		},
		{
			name: "with single empty string in file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				patterns: []string{""},
			},
			want: "sha256:17d6090b9a567b40432b74d8aed0a2344444dde05dd2de5e3a9a0d40dcfc2cfc",
		},
		{
			name: "with single non empty string in file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				patterns: []string{"test"},
			},
			want: "sha256:17d6090b9a567b40432b74d8aed0a2344444dde05dd2de5e3a9a0d40dcfc2cfc",
		},
		{
			name: "with non empty followed by empty string in file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				patterns: []string{"test", ""},
			},
			want: "sha256:17d6090b9a567b40432b74d8aed0a2344444dde05dd2de5e3a9a0d40dcfc2cfc",
		},
		{
			name: "with non empty preceded by empty string in file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				patterns: []string{"", "test"},
			},
			want: "sha256:17d6090b9a567b40432b74d8aed0a2344444dde05dd2de5e3a9a0d40dcfc2cfc",
		},
		{
			name: "with policy",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				policy: []string{"testdata"},
			},
			want: "sha256:4d2a6e6a86277040a5ccac3cac7f76878bb6636e646a41d8049d621d02410b96",
		},
		{
			name: "skip files and dirs",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				skipFiles: []string{"app/deployment.yaml"},
				skipDirs:  []string{"usr/java"},
				policy:    []string{"testdata"},
			},
			want: "sha256:f60f4e88a501e4599a71c962521a3914981b016b9073ade6b00cb2c34e9229a6",
		},
		{
			name: "with policy/non-existent dir",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				policy: []string{"policydir"},
			},
			wantErr: "no such file or directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifactOpt := artifact.Option{
				SkipFiles: tt.args.skipFiles,
				SkipDirs:  tt.args.skipDirs,
			}
			scannerOpt := config.ScannerOption{
				FilePatterns: tt.args.patterns,
				PolicyPaths:  tt.args.policy,
				DataPaths:    tt.args.data,
			}
			got, err := CalcKey(tt.args.key, tt.args.analyzerVersions, tt.args.hookVersions, artifactOpt, scannerOpt)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
