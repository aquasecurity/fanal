package walker

import (
	"testing"

	"github.com/aquasecurity/fanal/analyzer/library"

	"github.com/stretchr/testify/assert"
)

func Test_isIgnore(t *testing.T) {
	tests := []struct {
		name string
		dirs []string
		want bool
	}{
		{
			name: "ignore dirs",
			dirs: ignoreDirs,
			want: true,
		},
		{
			name: "ignore system dirs",
			dirs: ignoreSystemDirs,
			want: true,
		},
		{
			name: "ignore library dirs",
			dirs: library.IgnoreDirs,
			want: true,
		},
		{
			name: "ignore dir in dirs slash separator",
			dirs: []string{"foo/.git", "foo/node_modules"},
			want: true,
		},
		{
			name: "ignore dir in backslash separator",
			dirs: []string{`foo\.git`, `foo\node_modules`},
			want: true,
		},
		{
			name: "not ignore dirs",
			dirs: []string{"foo", "foo/bar"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.want {
				for _, fp := range tt.dirs {
					assert.True(t, isIgnored(fp))
				}
			} else {
				for _, fp := range tt.dirs {
					assert.False(t, isIgnored(fp))
				}
			}
		})
	}
}
