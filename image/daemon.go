package image

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	"golang.org/x/xerrors"

	"github.com/containerd/containerd/namespaces"
	"github.com/aquasecurity/fanal/image/daemon"
	"github.com/aquasecurity/fanal/types"
)

const (
	defaultContainerdSocket = "/run/containerd/containerd.sock"
	defaultContainerdNamespace = "default"
)

func tryDockerDaemon(imageName string, ref name.Reference) (types.Image, func(), error) {
	img, cleanup, err := daemon.DockerImage(ref)
	if err != nil {
		return nil, nil, err
	}
	return daemonImage{
		Image: img,
		name:  imageName,
	}, cleanup, nil

}

func tryPodmanDaemon(ref string) (types.Image, func(), error) {
	img, cleanup, err := daemon.PodmanImage(ref)
	if err != nil {
		return nil, nil, err
	}
	return daemonImage{
		Image: img,
		name:  ref,
	}, cleanup, nil
}

func tryContainerdDaemon(imageName string, ref name.Reference) (types.Image, func(), error) {
	ctx := context.Background()
	ctx = namespaces.WithNamespace(ctx, defaultContainerdNamespace)
	ci, err := daemon.NewContainerd(defaultContainerdSocket, ref.Name(), ctx)
	if err != nil {
		return nil, nil, xerrors.Errorf("tryContainerdDaemon: failed to initialize a docker client: %w", err)
	}
	img, cleanup, err := daemon.ContainerdImage(ci, ref, ctx)
	if err != nil {
		return nil, nil, err
	}
	return daemonImage{
		Image: img,
		name:  imageName,
	}, cleanup, nil
}

type daemonImage struct {
	daemon.Image
	name string
}

func (d daemonImage) Name() string {
	return d.name
}

func (d daemonImage) ID() (string, error) {
	return ID(d)
}

func (d daemonImage) LayerIDs() ([]string, error) {
	return LayerIDs(d)
}
