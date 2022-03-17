package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/images/archive"
	"github.com/containerd/containerd/platforms"
	"github.com/docker/docker/api/types/container"
	"github.com/google/go-containerregistry/pkg/name"
	"golang.org/x/xerrors"

	api "github.com/docker/docker/api/types"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type ImageReference struct {
	Named  string
	Tag    string
	Digest string
}

type ContainerdInterface interface {
	GetImageConfig(context.Context) (ocispec.Descriptor, error)
	ImageWriter(context.Context, []string) (io.ReadCloser, error)
	Close() error
	GetOCIImageBytes(context.Context) ([]byte, error)
}

type imageInstance struct {
	client  *containerd.Client
	refName string
	img     containerd.Image
}

func (cc *imageInstance) GetImageConfig(ctx context.Context) (ocispec.Descriptor, error) {
	img, err := cc.client.GetImage(ctx, cc.refName)
	if err != nil {
		return ocispec.Descriptor{}, xerrors.Errorf("GetImageConfig:: failed to get Image by: %v, err: %v", cc.refName, err)
	}
	return img.Config(ctx)
}

func (cc *imageInstance) Close() error {
	cc.client.Close()
	return nil
}

func (cc *imageInstance) ImageWriter(ctx context.Context, ref []string) (io.ReadCloser, error) {
	if len(ref) == 0 {
		return nil, xerrors.Errorf("imageWriter: failed to get iamge name: %v", ref)
	}
	imgOpts := archive.WithImage(cc.client.ImageService(), ref[0])
	manifestOpts := archive.WithManifest(cc.img.Target())
	platOpts := archive.WithPlatform(platforms.Default())
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(archive.Export(ctx, cc.client.ContentStore(), pw, imgOpts, manifestOpts, platOpts))
	}()
	return pr, nil
}

func (cc *imageInstance) GetOCIImageBytes(ctx context.Context) ([]byte, error) {
	cfg, err := cc.img.Config(ctx)
	if err != nil {
		return nil, xerrors.Errorf("GetOCIImageBytes:: failed to get img config, err: %v", err)
	}
	data, err := content.ReadBlob(ctx, cc.img.ContentStore(), cfg)
	if err != nil {
		return nil, xerrors.Errorf("GetOCIImageBytes:: failed to read blob: %v", err)
	}
	return data, nil
}

// ContainerdImage implements v1.Image by extending
func ContainerdImage(containerdSocket string, ref name.Reference, ctx context.Context) (Image, func(), error) {
	cleanup := func() {}
	cli, err := containerd.New(containerdSocket)

	if err != nil {
		return nil, cleanup, xerrors.Errorf("tryContainerdDaemon: failed to initialize a docker client: %w", err)
	}

	i, err := cli.GetImage(ctx, ref.Name())

	if err != nil {
		return nil, cleanup, err
	}

	ci := &imageInstance{client: cli, refName: ref.Name(), img: i}

	inspect, err := imageInspect(ctx, ref, ci)

	if err != nil {
		return nil, cleanup, err
	}

	var f *os.File
	cleanup = func() {
		ci.Close()
		f.Close()
		_ = os.Remove(f.Name())
	}
	f, err = os.CreateTemp("", "fanal-*")
	if err != nil {
		return nil, cleanup, xerrors.Errorf("ContainerImage: failed to create a temporary file")
	}

	return &image{
		opener:  imageOpener(ctx, ref.Name(), f, ci.ImageWriter),
		inspect: inspect,
	}, cleanup, nil
}

// imageInspect returns ImageInspect struct
func imageInspect(ctx context.Context, ref name.Reference, ci ContainerdInterface) (inspect api.ImageInspect, err error) {
	descriptor, err := ci.GetImageConfig(ctx)
	if err != nil {
		return api.ImageInspect{}, err
	}

	ociImage, err := containerToOci(ctx, descriptor, ci)
	if err != nil {
		return api.ImageInspect{}, err
	}
	var createAt string
	if ociImage.Created != nil {
		createAt = ociImage.Created.Format(time.RFC3339Nano)
	}

	var architecture string
	if descriptor.Platform != nil {
		architecture = descriptor.Platform.Architecture
	} else {
		architecture = ociImage.Architecture
	}

	return api.ImageInspect{
		Architecture: architecture,
		Config:       getImageInfoConfigFromOciImage(ociImage),
		Created:      createAt,
		ID:           string(descriptor.Digest),
		Os:           ociImage.OS,
		RepoDigests:  []string{fmt.Sprintf("%s@%s", ref.Context().String(), string(descriptor.Digest))},
		RepoTags:     []string{ref.Name()},
		RootFS: api.RootFS{
			Type:   ociImage.RootFS.Type,
			Layers: digestToString(ociImage.RootFS.DiffIDs),
		},
		Size: descriptor.Size,
	}, nil
}

func digestToString(digests []digest.Digest) []string {
	strs := make([]string, 0, len(digests))
	for _, d := range digests {
		strs = append(strs, d.String())
	}
	return strs
}

// getImageInfoConfigFromOciImage creates an instance of container.Config based on ocispec.ImageConfig
func getImageInfoConfigFromOciImage(img ocispec.Image) *container.Config {
	volumes := make(map[string]struct{})
	for k, obj := range img.Config.Volumes {
		volumes[k] = obj
	}

	return &container.Config{
		User:       img.Config.User,
		Env:        img.Config.Env,
		Entrypoint: img.Config.Entrypoint,
		Cmd:        img.Config.Cmd,
		WorkingDir: img.Config.WorkingDir,
		Labels:     img.Config.Labels,
		StopSignal: img.Config.StopSignal,
		Volumes:    volumes,
	}
}

func containerToOci(ctx context.Context, cfg ocispec.Descriptor, ci ContainerdInterface) (ocispec.Image, error) {
	var ociImage ocispec.Image

	switch cfg.MediaType {
	case ocispec.MediaTypeImageConfig, images.MediaTypeDockerSchema2Config, "application/octet-stream":
		data, err := ci.GetOCIImageBytes(ctx)
		if err != nil {
			return ocispec.Image{}, err
		}
		err = json.Unmarshal(data, &ociImage)
		if err != nil {
			return ocispec.Image{}, err
		}
	default:
		return ocispec.Image{}, xerrors.Errorf("containerToOci: invalid image config media type: %v", cfg.MediaType)
	}
	return ociImage, nil
}
