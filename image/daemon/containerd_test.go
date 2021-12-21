package daemon

import (
	"testing"

	"github.com/docker/docker/api/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
)

func TestContainerdImage(t *testing.T) {
	type fields struct {
		Image   v1.Image
		opener  opener
		inspect types.ImageInspect
	}
}

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

func TestSplitReference(t *testing.T) {
	tests := []struct {
		ref    string
		name   string
		tag    string
		digStr string
	}{
		{
			ref:    "nginx@sha256:2e87d9ff130deb0c2d63600390c3f2370e71e71841573990d54579bc35046203",
			name:   "nginx",
			digStr: "sha256:2e87d9ff130deb0c2d63600390c3f2370e71e71841573990d54579bc35046203",
			tag:    "",
		},
		{
			ref:    "nginx:latest",
			name:   "nginx",
			tag:    "latest",
			digStr: "",
		},
	}

	for _, test := range tests {
		name, tag, digStr := splitReference(test.ref)
		assert.Equal(t, test.name, name)
		assert.Equal(t, test.tag, tag)
		assert.Equal(t, test.digStr, digStr)
	}
}
