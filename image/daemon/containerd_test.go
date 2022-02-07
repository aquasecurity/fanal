package daemon

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

func TestContainerdImage(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	mockedC := NewMockContainerd(mockCtl)
	imgName := "geyingqi/dockercontainerd:alpine"
	ctx := context.Background()
	img := ocispec.Image{
		Author:       "",
		Architecture: "amd64",
		OS:           "linux",
		Config: ocispec.ImageConfig{
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"CONTAINERD_VERSION=main",
				"CONTAINERD_REVISION=9c676e98dde995db46841a2c6126ad709e3fc7d7",
			},
			Entrypoint: []string{"/usr/local/bin/containerd"},
		},
		RootFS: ocispec.RootFS{
			Type: "layers",
			DiffIDs: []digest.Digest{
				"sha256:7fcb75871b2101082203959c83514ac8a9f4ecfee77a0fe9aa73bbe56afdf1b4",
				"sha256:d8e6621ef4f1988bc908f54bf28211855113c4704da0f5d23defbfb9e68e069e",
				"sha256:4f565cc2300d2a1cabee1601e588193f1b0bc2e9c9c3fe552404b22a5c85d908",
				"sha256:d75a1c7574106e38fb5962f9654675d6d8310340a6fcf5d636774009a5437328",
			},
		},
	}
	imgBytes, err := json.Marshal(img)
	assert.NoError(t, err)
	test := struct {
		ociConfig     ocispec.Descriptor
		imageBytes    []byte
		imageName     string
		imgReadCloser io.ReadCloser
	}{
		ociConfig: ocispec.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    "sha256:eeff5658ca7390778dc69bc2fba1f119c303876430becb9cf8249bae85151dac",
			Size:      144441331,
			Platform: &ocispec.Platform{
				Architecture: "amd64",
				OS:           "linux",
				OSVersion:    "",
				OSFeatures:   []string{},
				Variant:      "",
			},
		},
		imageBytes:    imgBytes,
		imageName:     imgName,
		imgReadCloser: io.NopCloser(strings.NewReader(imgName)),
	}

	gomock.InOrder(
		mockedC.EXCEPT().GetImageConfig(gomock.Any()).Return(test.ociConfig, nil).AnyTimes(),
		mockedC.EXCEPT().GetOCIImageBytes(gomock.Any()).Return(test.imageBytes, nil).AnyTimes(),
		mockedC.EXCEPT().GetImageName(gomock.Any()).Return(test.imageName, nil).AnyTimes(),
		mockedC.EXCEPT().GetImageConfig(gomock.Any()).Return(test.ociConfig, nil),
		mockedC.EXCEPT().Close().Return(nil).AnyTimes(),
		mockedC.EXCEPT().ImageWriter(gomock.Any(), gomock.Any()).Return(test.imgReadCloser, nil).AnyTimes(),
	)
	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)
	ref, err := name.ParseReference(imgName, nameOpts...)
	assert.NoError(t, err)
	_, _, err = ContainerdImage(mockedC, ref, ctx)
	assert.NoError(t, err)
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
