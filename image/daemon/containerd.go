package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/images/archive"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/platforms"
	refdocker "github.com/containerd/containerd/reference/docker"
	"github.com/containerd/nerdctl/pkg/imageinspector"
	"github.com/containerd/nerdctl/pkg/inspecttypes/dockercompat"
	api "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"golang.org/x/xerrors"
)

const (
	defaultContainerdSocket    = "/run/containerd/containerd.sock"
	defaultContainerdNamespace = "default"
	rootUserUid                = "0"
)

var (
	// arg0 is UID of the Linux Namespace in which containerd runs
	rootlessContainerdDirFormat = "/proc/%s/root"

	// arg0 is UID of execute user
	rootlessChildPIDPathFormat = "/run/user/%s/containerd-rootless/child_pid"
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

// containerdAddr is get containerd socket address
func containerdAddr() (string, error) {
	addr := os.Getenv("CONTAINERD_ADDRESS")
	if addr == "" {
		u, err := user.Current()
		if err != nil {
			return "", xerrors.Errorf("failed to get current user: %w", err)
		}

		if u.Uid != rootUserUid {
			childPIDFilePath := fmt.Sprintf(rootlessChildPIDPathFormat, u.Uid)
			if _, err := os.Stat(childPIDFilePath); errors.Is(err, os.ErrNotExist) {
				return "", xerrors.Errorf("child pid file not found: %s", addr)
			}

			childPID, err := os.ReadFile(childPIDFilePath)
			if err != nil {
				return "", xerrors.Errorf("failed to read chile pid file: %w", err)
			}

			addr = filepath.Join(fmt.Sprintf(rootlessContainerdDirFormat, childPID), addr)
		} else {
			addr = defaultContainerdSocket
		}
	}

	if _, err := os.Stat(addr); errors.Is(err, os.ErrNotExist) {
		return "", xerrors.Errorf("containerd socket not found: %s", addr)
	}
	return addr, nil
}

// ContainerdImage implements v1.Image
func ContainerdImage(ctx context.Context, imageName string) (Image, func(), error) {
	cleanup := func() {}

	addr, err := containerdAddr()
	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to get containerd address: %w", err)
	}

	// Parse the image name
	ref, err := refdocker.ParseDockerRef(imageName)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("parse error: %w", err)
	}

	client, err := containerd.New(addr)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to initialize a containerd client: %w", err)
	}

	// Need to specify a namespace
	ctx = namespaces.WithNamespace(ctx, defaultContainerdNamespace)

	img, err := client.GetImage(ctx, ref.String())
	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to get %s: %w", imageName, err)
	}

	// Inspect the image
	n, err := imageinspector.Inspect(ctx, client, img.Metadata())
	if err != nil {
		return nil, cleanup, xerrors.Errorf("inspect error: %w", imageName, err)
	}

	// Convert the result to the docker compat format
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
		opener:  imageOpener(ctx, ref.String(), f, imageWriter(client, img)),
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
