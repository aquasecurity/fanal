package image

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/aquasecurity/fanal/image/daemon"
	"github.com/aquasecurity/fanal/types"
	"github.com/containerd/containerd/namespaces"
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
	ctx := namespaces.WithNamespace(context.Background(), daemon.DefaultContainerdNamespace)

	img, cleanup, err := daemon.ContainerdImage(daemon.DefaultContainerdSocket, imageName, ref, ctx)

	if err != nil {
		return nil, cleanup, err
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
