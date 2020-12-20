package image

import (
	"github.com/aquasecurity/fanal/image/daemon"
	"github.com/docker/docker/api/types"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func tryDaemon(ref name.Reference) (v1.Image, extender, func(), error) {
	img, inspect, cleanup, err := daemon.Image(ref)
	if err != nil {
		return nil, nil, nil, err
	}
	return img, daemonExtender{inspect: inspect}, cleanup, nil

}

type daemonExtender struct {
	inspect *types.ImageInspect
}

func (e daemonExtender) RepoTags() []string {
	return e.inspect.RepoTags
}

func (e daemonExtender) RepoDigests() []string {
	return e.inspect.RepoDigests
}
