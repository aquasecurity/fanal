package daemon

import (
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
)

func TestDigestToString(t *testing.T) {
	test1Str := "test1"
	emptyStr := ""

	tests := []struct {
		digests    []digest.Digest
		wantedStrs []string
	}{
		{
			digests:    []digest.Digest{digest.NewDigestFromEncoded(digest.SHA256, test1Str)},
			wantedStrs: []string{digest.SHA256.String() + ":" + test1Str},
		},
		{
			digests:    []digest.Digest{digest.NewDigestFromEncoded(digest.SHA256, emptyStr)},
			wantedStrs: []string{digest.SHA256.String() + ":" + emptyStr},
		},
	}
	for _, test := range tests {
		r := digestToString(test.digests)
		assert.Equal(t, r, test.wantedStrs)
	}
}
