package gemspec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_pipAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "with default",
			filePath: "usr/ank/specifications/default/ank.gemspec",
			want:     true,
		},
		{
			name:     "without default",
			filePath: "usr/ank/specifications/ank.gemspec",
			want:     true,
		},
		{
			name:     "source gemspec",
			filePath: "/localtRepo/default/ank.gemspec",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := gemspecLibraryAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
