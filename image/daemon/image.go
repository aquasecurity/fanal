package daemon

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	dimage "github.com/docker/docker/api/types/image"

	"github.com/araddon/dateparse"
	"github.com/docker/docker/api/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"golang.org/x/xerrors"
)

var mu sync.Mutex

type opener func() (v1.Image, error)

type imageSave func(context.Context, []string) (io.ReadCloser, error)

func imageOpener(ref string, f *os.File, imageSave imageSave) opener {
	return func() (v1.Image, error) {
		// Store the tarball in local filesystem and return a new reader into the bytes each time we need to access something.
		rc, err := imageSave(context.Background(), []string{ref})
		if err != nil {
			return nil, xerrors.Errorf("unable to export the image: %w", err)
		}
		defer rc.Close()

		if _, err = io.Copy(f, rc); err != nil {
			return nil, xerrors.Errorf("failed to copy the image: %w", err)
		}
		defer f.Close()

		image, err := tarball.ImageFromPath(f.Name(), nil)
		if err != nil {
			return nil, xerrors.Errorf("failed to initialize the struct from the temporary file: %w", err)
		}

		return image, nil
	}
}

// image is a wrapper for github.com/google/go-containerregistry/pkg/v1/daemon.Image
// daemon.Image loads the entire image into the memory at first,
// but it doesn't need to load it if the information is already in the cache,
// To avoid entire loading, this wrapper uses ImageInspectWithRaw and checks image ID and layer IDs.
type image struct {
	v1.Image
	opener  opener
	inspect types.ImageInspect
	history []dimage.HistoryResponseItem
}

// populateImage initializes an "image" struct.
// This method is called by some goroutines at the same time.
// To prevent multiple heavy initializations, the lock is necessary.
func (img *image) populateImage() (err error) {
	mu.Lock()
	defer mu.Unlock()

	// img.Image is already initialized, so we don't have to do it again.
	if img.Image != nil {
		return nil
	}

	img.Image, err = img.opener()
	if err != nil {
		return xerrors.Errorf("unable to open: %w", err)
	}

	return nil
}

func (img *image) ConfigName() (v1.Hash, error) {
	return v1.NewHash(img.inspect.ID)
}

func (img *image) ConfigFile() (*v1.ConfigFile, error) {
	if len(img.inspect.RootFS.Layers) == 0 {
		// Podman doesn't return RootFS...
		if err := img.populateImage(); err != nil {
			return nil, xerrors.Errorf("unable to populate: %w", err)
		}
		return img.Image.ConfigFile()
	}
	var diffIDs []v1.Hash
	for _, l := range img.inspect.RootFS.Layers {
		h, err := v1.NewHash(l)
		if err != nil {
			return nil, xerrors.Errorf("invalid hash %s: %w", l, err)
		}
		diffIDs = append(diffIDs, h)
	}

	// fill only required metadata
	var layersHistory []v1.History
	var layerCreatedDate time.Time
	var isEmptyLayer bool
	for _, history := range img.history {
		layerCreatedDate = time.Unix(history.Created, 0).UTC()
		isEmptyLayer = false
		if history.Size == 0 {
			isEmptyLayer = true
		}
		configHistory := v1.History{
			Author:     history.CreatedBy,
			Created:    v1.Time{Time: layerCreatedDate},
			CreatedBy:  history.CreatedBy,
			Comment:    history.Comment,
			EmptyLayer: isEmptyLayer,
		}
		layersHistory = append(layersHistory, configHistory)
	}

	// NOTE:  This is very, very important to understand time-parsing in go
	loc, err := time.LoadLocation("")
	if err != nil {
		return nil, xerrors.Errorf("failed setting location %s: %w", img.inspect.Created, err)
	}
	time.Local = loc
	imgCreatedDate, err := dateparse.ParseLocal(img.inspect.Created)
	fmt.Println(imgCreatedDate)
	if err != nil {
		return nil, xerrors.Errorf("failed parsing created Date %s: %w", img.inspect.Created, err)
	}

	return &v1.ConfigFile{
		Architecture:  img.inspect.Architecture,
		Author:        img.inspect.Author,
		Created:       v1.Time{Time: imgCreatedDate},
		DockerVersion: img.inspect.DockerVersion,
		Config:        v1.Config{Labels: img.inspect.Config.Labels, Env: img.inspect.Config.Env},
		History:       layersHistory,
		RootFS: v1.RootFS{
			Type:    img.inspect.RootFS.Type,
			DiffIDs: diffIDs,
		},
	}, nil
}

func (img *image) LayerByDiffID(h v1.Hash) (v1.Layer, error) {
	if err := img.populateImage(); err != nil {
		return nil, xerrors.Errorf("unable to populate: %w", err)
	}
	return img.Image.LayerByDiffID(h)
}

func (img *image) RawConfigFile() ([]byte, error) {
	if err := img.populateImage(); err != nil {
		return nil, xerrors.Errorf("unable to populate: %w", err)
	}
	return img.Image.RawConfigFile()
}
