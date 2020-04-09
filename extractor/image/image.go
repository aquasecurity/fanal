package image

import (
	"context"
	"io"
	"io/ioutil"
	"os"

	"github.com/containers/image/v5/image"
	"github.com/containers/image/v5/pkg/blobinfocache"
	"github.com/containers/image/v5/pkg/compression"
	"github.com/containers/image/v5/transports/alltransports"
	imageTypes "github.com/containers/image/v5/types"
	"github.com/docker/distribution/reference"
	digest "github.com/opencontainers/go-digest"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/types"
)

type ImageSource interface {
	GetBlob(ctx context.Context, info imageTypes.BlobInfo, cache imageTypes.BlobInfoCache) (reader io.ReadCloser, n int64, err error)
	Close() error
}

type ImageCloser interface {
	LayerInfos() (layerInfos []imageTypes.BlobInfo)
	ConfigInfo() imageTypes.BlobInfo
	ConfigBlob(context.Context) ([]byte, error)
	Close() error
}

type Reference struct {
	Name   string
	IsFile bool
}

type Image interface {
	Name() (name string)
	LayerIDs() (layerIDs []string)
	ConfigInfo() imageTypes.BlobInfo
	ConfigBlob(context.Context) ([]byte, error)
	GetLayer(ctx context.Context, dig digest.Digest) (reader io.ReadCloser, err error)
	Close() (err error)
}

type RealImage struct {
	name          string // image name or tar file name
	blobInfoCache imageTypes.BlobInfoCache
	rawSource     ImageSource
	src           ImageCloser
}

func NewImage(ctx context.Context, image Reference, transports []string, option types.DockerOption) (RealImage, func(), error) {
	var domain string
	var auth *imageTypes.DockerAuthConfig
	var err error

	originalName := image.Name
	if !image.IsFile {
		named, err := reference.ParseNormalizedNamed(image.Name)
		if err != nil {
			return RealImage{}, nil, xerrors.Errorf("invalid image name: %w", err)
		}

		// add 'latest' tag
		named = reference.TagNameOnly(named)
		image.Name = named.String()

		// get a credential for Docker registry
		domain = reference.Domain(named)
		auth = GetToken(ctx, domain, option)
	}

	// Receive an image content from stdin
	var tmpImageFileName string
	if image.IsFile && image.Name == "-" && !terminal.IsTerminal(0) {
		tmpImageFileName, err = copyStdinToTempFile()
		if err != nil {
			return RealImage{}, nil, err
		}
		image.Name = tmpImageFileName
	}

	sys := &imageTypes.SystemContext{
		// TODO: make OSChoice configurable
		OSChoice:                          "linux",
		DockerAuthConfig:                  auth,
		DockerDisableV1Ping:               option.SkipPing,
		DockerInsecureSkipTLSVerify:       imageTypes.NewOptionalBool(option.InsecureSkipTLSVerify),
		OCIInsecureSkipTLSVerify:          option.InsecureSkipTLSVerify,
		DockerDaemonCertPath:              option.DockerDaemonCertPath,
		DockerDaemonHost:                  option.DockerDaemonHost,
		DockerDaemonInsecureSkipTLSVerify: option.InsecureSkipTLSVerify,
	}

	rawSource, src, err := newSource(ctx, image.Name, transports, sys)
	if err != nil {
		return RealImage{}, nil, xerrors.Errorf("failed to initialize source: %w", err)
	}

	img := RealImage{
		name:          originalName,
		blobInfoCache: blobinfocache.DefaultCache(sys),
		rawSource:     rawSource,
		src:           src,
	}

	cleanup := func() {
		if tmpImageFileName != "" {
			_ = os.Remove(tmpImageFileName)
		}
		_ = img.Close()
	}

	return img, cleanup, nil
}

func copyStdinToTempFile() (string, error) {
	tmpImageFile, err := ioutil.TempFile("", "fanal")
	if err != nil {
		return "", xerrors.Errorf("unable to create a temp file: %w", err)
	}

	if _, err = io.Copy(tmpImageFile, os.Stdin); err != nil {
		return "", xerrors.Errorf("unable to copy stdin to a temp file: %w", err)
	}
	return tmpImageFile.Name(), nil
}

func newSource(ctx context.Context, imageName string, transports []string, sys *imageTypes.SystemContext) (
	ImageSource, ImageCloser, error) {
	err := xerrors.New("no valid transport")
	for _, transport := range transports {
		imgName := transport + imageName
		var ref imageTypes.ImageReference
		ref, err = alltransports.ParseImageName(imgName)
		if err != nil {
			return nil, nil, xerrors.Errorf("failed to parse an image name: %w", err)
		}

		var rawSource imageTypes.ImageSource
		rawSource, err = ref.NewImageSource(ctx, sys)
		if err != nil {
			// try next transport
			continue
		}

		var src imageTypes.ImageCloser
		src, err = image.FromSource(ctx, sys, rawSource)
		if err != nil {
			return nil, nil, xerrors.Errorf("failed to initialize: %w", err)
		}

		return rawSource, src, nil
	}
	// return only the last error
	return nil, nil, err
}

func (img RealImage) Name() string {
	return img.name
}

func (img RealImage) LayerIDs() []string {
	var layerIDs []string
	for _, l := range img.src.LayerInfos() {
		layerIDs = append(layerIDs, string(l.Digest))
	}
	return layerIDs
}

func (img RealImage) ConfigInfo() imageTypes.BlobInfo {
	return img.src.ConfigInfo()
}

func (img RealImage) ConfigBlob(ctx context.Context) ([]byte, error) {
	b, err := img.src.ConfigBlob(ctx)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (img RealImage) GetLayer(ctx context.Context, dig digest.Digest) (io.ReadCloser, error) {
	rc, _, err := img.rawSource.GetBlob(ctx, imageTypes.BlobInfo{Digest: dig, Size: -1}, img.blobInfoCache)
	if err != nil {
		return nil, xerrors.Errorf("failed to download the layer(%s): %w", dig, err)
	}

	stream, _, err := compression.AutoDecompress(rc)
	if err != nil {
		return nil, xerrors.Errorf("failed to download the layer(%s): %w", dig, err)
	}

	return stream, nil
}

func (img RealImage) Close() error {
	if img.src != nil {
		if err := img.src.Close(); err != nil {
			return xerrors.Errorf("unable to close image source: %w", err)
		}
	}
	if img.rawSource != nil {
		if err := img.rawSource.Close(); err != nil {
			return xerrors.Errorf("unable to close image source: %w", err)
		}
	}
	return nil
}
