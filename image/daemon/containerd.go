package daemon

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/images/archive"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/nerdctl/pkg/imageinspector"
	"github.com/containerd/nerdctl/pkg/inspecttypes/dockercompat"
	api "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"golang.org/x/xerrors"
)

const (
	DefaultContainerdSocket    = "/run/containerd/containerd.sock"
	DefaultContainerdNamespace = "default"
)

func imageWriter(client *containerd.Client, img containerd.Image) imageSave {
	return func(ctx context.Context, ref []string) (io.ReadCloser, error) {
		if len(ref) < 1 {
			return nil, xerrors.New("no image reference")
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

// ContainerdImage implements v1.Image
func ContainerdImage(containerdSocket, imageName string, ctx context.Context) (Image, func(), error) {
	cleanup := func() {}

	if _, err := os.Stat(containerdSocket); errors.Is(err, os.ErrNotExist) {
		return nil, cleanup, xerrors.Errorf("containerd socket not found: %s", containerdSocket)
	}

	client, err := containerd.New(containerdSocket)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to initialize a containerd client: %w", err)
	}

	img, err := client.GetImage(ctx, imageName)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to get %s: %w", imageName, err)
	}

	n, err := imageinspector.Inspect(ctx, client, img.Metadata())
	if err != nil {
		return nil, cleanup, xerrors.Errorf("inspect error: %w", imageName, err)
	}

	d, err := dockercompat.ImageFromNative(n)
	if err != nil {
		return nil, cleanup, err
	}

	f, err := os.CreateTemp("", "fanal-containerd-*")
	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to create a temporary file: %w", err)
	}

	cleanup = func() {
		_ = client.Close()
		_ = f.Close()
		_ = os.Remove(f.Name())
	}

	return &image{
		opener:  imageOpener(ctx, imageName, f, imageWriter(client, img)),
		inspect: toDockerInspect(d),
	}, cleanup, nil
}

func toDockerInspect(d *dockercompat.Image) api.ImageInspect {
	return api.ImageInspect{
		ID:          d.ID,
		RepoTags:    d.RepoTags,
		RepoDigests: d.RepoDigests,
		Comment:     d.Comment,
		Created:     d.Created,
		Author:      d.Author,
		Config: &container.Config{
			User:         d.Config.User,
			ExposedPorts: d.Config.ExposedPorts,
			Env:          d.Config.Env,
			Cmd:          d.Config.Cmd,
			Volumes:      d.Config.Volumes,
			WorkingDir:   d.Config.WorkingDir,
			Entrypoint:   d.Config.Entrypoint,
			Labels:       d.Config.Labels,
		},
		Architecture: d.Architecture,
		Os:           d.Os,
		RootFS: api.RootFS{
			Type:      d.RootFS.Type,
			Layers:    d.RootFS.Layers,
			BaseLayer: d.RootFS.BaseLayer,
		},
		Metadata: api.ImageMetadata{
			LastTagTime: d.Metadata.LastTagTime,
		},
	}
}
