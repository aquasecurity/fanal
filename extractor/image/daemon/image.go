package daemon

import (
	"context"
	"io"
	"io/ioutil"
	"os"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"golang.org/x/xerrors"
)

var mu sync.Mutex

// image is a wrapper for github.com/google/go-containerregistry/pkg/v1/daemon.Image
// daemon.Image loads the entire image into the memory at first,
// but it doesn't need to load it if the information is already in the cache,
// To avoid entire loading, this wrapper uses ImageInspectWithRaw and checks image ID and layer IDs.
type image struct {
	v1.Image
	opener  opener
	inspect types.ImageInspect
}

type opener func() (v1.Image, error)

// Image implements v1.Image by extending daemon.Image.
// The caller must call cleanup() to remove a temporary file.
func Image(ref name.Reference) (v1.Image, func(), error) {
	cleanup := func() {}

	c, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to initialize a docker client: %w", err)
	}

	c.NegotiateAPIVersion(context.Background())

	inspect, _, err := c.ImageInspectWithRaw(context.Background(), ref.Name())
	if err != nil {
		return nil, cleanup, err
	}

	f, err := ioutil.TempFile("", "fanal-*")
	if err != nil {
		return nil, cleanup, err
	}

	cleanup = func() {
		_ = os.Remove(f.Name())
	}

	return &image{
		opener:  imageOpener(c, ref, f),
		inspect: inspect,
	}, cleanup, nil
}

func imageOpener(c *client.Client, ref name.Reference, f *os.File) opener {
	return func() (v1.Image, error) {
		// Store the tarball in local filesystem and return a new reader into the bytes each time we need to access something.
		rc, err := c.ImageSave(context.Background(), []string{ref.Name()})
		if err != nil {
			return nil, xerrors.Errorf("foo: %w", err)
		}
		defer rc.Close()

		if _, err = io.Copy(f, rc); err != nil {
			return nil, xerrors.Errorf("foo: %w", err)
		}
		defer f.Close()

		image, err := tarball.ImageFromPath(f.Name(), nil)
		if err != nil {
			return nil, xerrors.Errorf("foo: %w", err)
		}

		return image, nil
	}
}

func (img *image) populateImage() (err error) {
	mu.Lock()
	defer mu.Unlock()

	if img.Image != nil {
		return nil
	}

	img.Image, err = img.opener()
	if err != nil {
		return xerrors.Errorf("open: %w", err)
	}

	return nil
}

func (img *image) ConfigName() (v1.Hash, error) {
	return v1.NewHash(img.inspect.ID)
}

func (img *image) ConfigFile() (*v1.ConfigFile, error) {
	var diffIDs []v1.Hash
	for _, l := range img.inspect.RootFS.Layers {
		h, err := v1.NewHash(l)
		if err != nil {
			return nil, err
		}
		diffIDs = append(diffIDs, h)
	}

	return &v1.ConfigFile{
		RootFS: v1.RootFS{
			Type:    img.inspect.RootFS.Type,
			DiffIDs: diffIDs,
		},
	}, nil
}

func (img *image) LayerByDiffID(h v1.Hash) (v1.Layer, error) {
	if err := img.populateImage(); err != nil {
		return nil, err
	}
	return img.Image.LayerByDiffID(h)
}

func (img *image) RawConfigFile() ([]byte, error) {
	if err := img.populateImage(); err != nil {
		return nil, err
	}
	return img.Image.RawConfigFile()
}
