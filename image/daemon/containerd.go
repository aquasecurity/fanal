package daemon

import (
	"context"
	"encoding/json"
	"errors"
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

const (
	DefaultContainerdSocket    = "/run/containerd/containerd.sock"
	DefaultContainerdNamespace = "default"
)

func imageWriter(client *containerd.Client, img containerd.Image) imageSave {

	return func(ctx context.Context, ref []string) (io.ReadCloser, error) {
		if len(ref) == 0 {
			return nil, xerrors.Errorf("imageWriter: failed to get iamge name: %v", ref)
		}
		imgOpts := archive.WithImage(client.ImageService(), ref[0])
		manifestOpts := archive.WithManifest(img.Target())
		platOpts := archive.WithPlatform(platforms.DefaultStrict())
		pr, pw := io.Pipe()
		go func() {
			pw.CloseWithError(archive.Export(ctx, client.ContentStore(), pw, imgOpts, manifestOpts, platOpts))
		}()
		return pr, nil
	}
}

// ContainerdImage implements v1.Image by extending
func ContainerdImage(containerdSocket, imageName string, ref name.Reference, ctx context.Context) (Image, func(), error) {
	cleanup := func() {}

	if _, err := os.Stat(containerdSocket); errors.Is(err, os.ErrNotExist) {
		return nil, cleanup, xerrors.Errorf("Socket doesn't exist: %s", containerdSocket)
	}

	cli, err := containerd.New(containerdSocket)

	if err != nil {
		return nil, cleanup, xerrors.Errorf("tryContainerdDaemon: failed to initialize a docker client: %w", err)
	}

	i, err := cli.GetImage(ctx, imageName)

	if err != nil {
		return nil, cleanup, err
	}

	inspect, err := imageInspect(ctx, i, ref)

	if err != nil {
		return nil, cleanup, err
	}

	var f *os.File
	cleanup = func() {
		cli.Close()
		f.Close()
		_ = os.Remove(f.Name())
	}
	f, err = os.CreateTemp("", "fanal-*")
	if err != nil {
		return nil, cleanup, xerrors.Errorf("ContainerImage: failed to create a temporary file")
	}

	return &image{
		opener:  imageOpener(ctx, imageName, f, imageWriter(cli, i)),
		inspect: inspect,
	}, cleanup, nil
}

// imageInspect returns ImageInspect struct
func imageInspect(ctx context.Context, img containerd.Image, ref name.Reference) (inspect api.ImageInspect, err error) {
	descriptor, err := img.Config(ctx)
	if err != nil {
		return api.ImageInspect{}, err
	}

	ociImage, err := containerdToOci(ctx, img, descriptor)
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
		RepoDigests:  []string{fmt.Sprintf("%s@%s", ref.Context().RepositoryStr(), string(descriptor.Digest))},
		RepoTags:     []string{fmt.Sprintf("%s:%s", ref.Context().RepositoryStr(), ref.Identifier())},
		RootFS: api.RootFS{
			Type:   ociImage.RootFS.Type,
			Layers: digestToString(ociImage.RootFS.DiffIDs),
		},
		Size: descriptor.Size,
	}, nil
}

// ocispec.Image -> *container.Config
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

// containerd.Image -> ocispec.Image
func containerdToOci(ctx context.Context, img containerd.Image, cfg ocispec.Descriptor) (ocispec.Image, error) {
	var ociImage ocispec.Image

	switch cfg.MediaType {
	case ocispec.MediaTypeImageConfig, images.MediaTypeDockerSchema2Config, "application/octet-stream":
		data, err := content.ReadBlob(ctx, img.ContentStore(), cfg)
		if err != nil {
			return ocispec.Image{}, xerrors.Errorf("GetOCIImageBytes:: failed to read blob: %v", err)
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

func digestToString(digests []digest.Digest) []string {
	strs := make([]string, 0, len(digests))
	for _, d := range digests {
		strs = append(strs, d.String())
	}
	return strs
}
