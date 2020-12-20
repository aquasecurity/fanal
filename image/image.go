package image

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/tls"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/aquasecurity/fanal/image/token"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	multierror "github.com/hashicorp/go-multierror"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/image/daemon"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

type extender interface {
	RepoTags() []string
	RepoDigests() []string
}

type Image struct {
	name   string
	client v1.Image
	extender
}

func (img Image) Name() string {
	return img.name
}

func (img Image) ID() (string, error) {
	h, err := img.client.ConfigName()
	if err != nil {
		return "", xerrors.Errorf("unable to get the image ID: %w", err)
	}
	return h.String(), nil
}

func (img Image) ConfigBlob() ([]byte, error) {
	return img.client.RawConfigFile()
}

func (img Image) LayerIDs() ([]string, error) {
	conf, err := img.client.ConfigFile()
	if err != nil {
		return nil, xerrors.Errorf("unable to get the config file: %w", err)
	}

	var layerIDs []string
	for _, d := range conf.RootFS.DiffIDs {
		layerIDs = append(layerIDs, d.String())
	}
	return layerIDs, nil
}

func (img Image) LayerByDiffID(h v1.Hash) (v1.Layer, error) {
	return img.client.LayerByDiffID(h)
}

func NewDockerImage(ctx context.Context, imageName string, option types.DockerOption) (Image, func(), error) {
	img, ext, cleanup, err := newDockerImage(ctx, imageName, option)
	if err != nil {
		return Image{}, func() {}, err
	}
	return Image{
		name:     imageName,
		client:   img,
		extender: ext,
	}, cleanup, nil
}

func newDockerImage(ctx context.Context, imageName string, option types.DockerOption) (v1.Image, extender, func(), error) {
	var errs error

	var nameOpts []name.Option
	if option.NonSSL {
		nameOpts = append(nameOpts, name.Insecure)
	}
	ref, err := name.ParseReference(imageName, nameOpts...)
	if err != nil {
		return nil, nil, func() {}, xerrors.Errorf("failed to parse the image name: %w", err)
	}

	// Try accessing Docker Daemon
	img, ext, cleanup, err := tryDaemon(ref)
	if err == nil {
		// Return v1.Image if the image is found in Docker Engine
		return img, ext, cleanup, nil
	}
	errs = multierror.Append(errs, err)

	// Try accessing Docker Registry
	var remoteOpts []remote.Option
	if option.InsecureSkipTLSVerify {
		t := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		remoteOpts = append(remoteOpts, remote.WithTransport(t))
	}

	domain := ref.Context().RegistryStr()
	auth := token.GetToken(ctx, domain, option)

	if auth.Username != "" && auth.Password != "" {
		remoteOpts = append(remoteOpts, remote.WithAuth(&auth))
	} else if option.RegistryToken != "" {
		bearer := authn.Bearer{Token: option.RegistryToken}
		remoteOpts = append(remoteOpts, remote.WithAuth(&bearer))
	} else {
		remoteOpts = append(remoteOpts, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	}

	img, err = remote.Image(ref, remoteOpts...)
	if err == nil {
		// Return v1.Image if the image is found in Docker Registry
		return img, func() {}, nil
	}
	result = multierror.Append(result, err)

	return nil, func() {}, result
}

func NewArchiveImage(fileName string) (Image, error) {
	img, err := newArchiveImage(fileName)
	if err != nil {
		return Image{}, err
	}
	return Image{
		name:   fileName,
		client: img,
	}, nil
}

func newArchiveImage(fileName string) (v1.Image, error) {
	var result error
	img, err := tryDockerArchive(fileName)
	if err == nil {
		// Return v1.Image if the file can be opened as Docker archive
		return img, nil
	}
	result = multierror.Append(result, err)

	img, err = tryOCI(fileName)
	if err == nil {
		// Return v1.Image if the directory can be opened as OCI Image Format
		return img, nil
	}
	result = multierror.Append(result, err)

	return nil, result
}


}

}
