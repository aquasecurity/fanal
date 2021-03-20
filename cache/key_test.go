package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer/config"
)

func TestCalcKey(t *testing.T) {
	type args struct {
		key     string
		version string
	}
	tests := []struct {
		name     string
		args     args
		patterns []string
		policy   []string
		data     []string
		want     string
		wantErr  string
		skip     string
	}{
		{
			name: "happy path",
			args: args{
				key:     "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				version: "111101112110013",
			},
			want: "sha256:1acfb4a0eb0acb0b1e8d462df18841581b960d5df190b32f3327df4820e5bc7b",
		},
		{
			name: "empty slice file patterns",
			args: args{
				key:     "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				version: "111101112110013",
			},
			patterns: []string{},
			want:     "sha256:1acfb4a0eb0acb0b1e8d462df18841581b960d5df190b32f3327df4820e5bc7b",
		},
		{
			name: "empty string in file patterns",
			args: args{
				key:     "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				version: "111101112110013",
			},
			patterns: []string{""},
			want:     "sha256:1acfb4a0eb0acb0b1e8d462df18841581b960d5df190b32f3327df4820e5bc7b",
		},
		{
			name: "multiple empty string in file patterns",
			args: args{
				key:     "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				version: "111101112110013",
			},
			patterns: []string{"", ""},
			want:     "sha256:1acfb4a0eb0acb0b1e8d462df18841581b960d5df190b32f3327df4820e5bc7b",
		},
		{
			name: "non empty string in file patterns",
			args: args{
				key:     "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				version: "111101112110013",
			},
			patterns: []string{"test"},
			want:     "sha256:7bbca3f56a19cc7d892879d17ba2204f62d37fd9122ca74271e5bb4ab0817bc1",
		},
		{
			name: "empty and non empty string in file patterns",
			args: args{
				key:     "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				version: "111101112110013",
			},
			patterns: []string{"test", ""},
			want:     "sha256:7bbca3f56a19cc7d892879d17ba2204f62d37fd9122ca74271e5bb4ab0817bc1",
		},
		{
			name: "empty slice policy paths",
			args: args{
				key:     "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				version: "111101112110013",
			},
			policy: []string{},
			want:   "sha256:1acfb4a0eb0acb0b1e8d462df18841581b960d5df190b32f3327df4820e5bc7b",
		},
		{
			name: "empty string in policy paths",
			skip: "returns unique hash on each run",
		},
		{
			name: "multiple empty string in policy paths",
			skip: "returns unique hash on each run, different hash from single empty string",
		},
		{
			name: "dot in policy paths",
			skip: "returns unique hash on each run, as it depends on dir content, different has from single empty string",
		},
		{
			name: "updir in policy paths",
			skip: "returns unique hash on each run, as it depends on dir content",
		},
		{
			name: "with policy",
			args: args{
				key:     "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				version: "111101112110013",
			},
			policy: []string{"testdata"},
			want:   "sha256:5e78e0f459400410c5c404d5d28676e03cd415a98483ccadb5080c605cd11315",
		},
		{
			name: "with policy/non-existent dir",
			args: args{
				key:     "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				version: "111101112110013",
			},
			policy: []string{"policydir"},
			want:   "",
		},
	}
	for _, tt := range tests {
		if tt.skip != "" {
			t.Logf("%s: skipped as not testable: %s", tt.name, tt.skip)
			continue
		}
		t.Run(tt.name, func(t *testing.T) {
			opt := &config.ScannerOption{
				FilePatterns: tt.patterns,
				PolicyPaths:  tt.policy,
				DataPaths:    tt.data,
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
