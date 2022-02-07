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

const (
	tagTemplate         = "%s:%s"
	digestTemplate      = "%s@%s"
)

type ImageReference struct {
	Named  string
	Tag    string
	Digest string
}

type ContainerdInterface interface {
	GetImageConfig(context.Context) (ocispec.Descriptor, error)
	GetImageName(context.Context) (string, error)
	ImageWriter(context.Context, []string) (io.ReadCloser, error)
	ContentStore(context.Context) (content.Store, error)
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

func (cc *imageInstance) ContentStore(ctx context.Context) (content.Store, error) {
	return cc.img.ContentStore(), nil
}

func (cc *imageInstance) GetImageName(ctx context.Context) (string, error) {
	return cc.img.Name(), nil
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

func NewContainerd(socket, refName string, ctx context.Context) (ContainerdInterface, error) {
	cli, err := containerd.New(socket)
	if err != nil {
		return &imageInstance{}, err
	}
	i, err := cli.GetImage(ctx, refName)
	if err != nil {
		return &imageInstance{}, err
	}

	return &imageInstance{client: cli, refName: refName, img: i}, nil
}

// ContainerdImage implements v1.Image by extending
func ContainerdImage(ci ContainerdInterface, ref name.Reference, ctx context.Context) (Image, func(), error) {
	cleanup := func() {}
	inspect, err := imageInspect(ctx, ci)
	defer func() {
		if err != nil {
			ci.Close()
		}
	}()
	if err != nil {
		return nil, cleanup, err
	}

	f, err := os.CreateTemp("", "fanal-*")
	if err != nil {
		return nil, cleanup, xerrors.Errorf("ContainerImage: failed to create a temporary file")
	}

	cleanup = func() {
		ci.Close()
		f.Close()
		_ = os.Remove(f.Name())
	}

	return &image{
		opener:  imageOpener(ctx, ref.Name(), f, ci.ImageWriter),
		inspect: inspect,
	}, cleanup, nil
}

// imageInspect returns ImageInspect struct
func imageInspect(ctx context.Context, ci ContainerdInterface) (inspect api.ImageInspect, err error) {
	descriptor, err := ci.GetImageConfig(ctx)
	if err != nil {
		return api.ImageInspect{}, err
	}
	ociImage, err := containerToOci(ctx, ci)
	if err != nil {
		return api.ImageInspect{}, err
	}
	var createAt string
	if ociImage.Created != nil {
		createAt = ociImage.Created.Format(time.RFC3339Nano)
	}
	repoDigests, repoTags := getRepoInfo(ctx, ci)
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
		RepoDigests:  repoDigests,
		RepoTags:     repoTags,
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

// getImageInfoConfigFromOciImage returns config of ImageConfig from oci image.
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

func containerToOci(ctx context.Context, ci ContainerdInterface) (ocispec.Image, error) {
	var ociImage ocispec.Image

	cfg, err := ci.GetImageConfig(ctx)
	if err != nil {
		return ocispec.Image{}, err
	}

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

// splitReference splits reference into name, tag and digest in string format.
func splitReference(ref string) (name string, tag string, digStr string) {
	name = ref

	if loc := regDigest.FindStringIndex(name); loc != nil {
		name, digStr = name[:loc[0]], name[loc[0]+1:]
	}

	if loc := regTag.FindStringIndex(name); loc != nil {
		name, tag = name[:loc[0]], name[loc[0]+1:]
	}
	return
}

// Parse parses ref into.
func Parse(ctx context.Context, imgRef string, conf ocispec.Descriptor) (ImageReference, error) {
	if ok := regRef.MatchString(imgRef); !ok {
		return ImageReference{}, xerrors.Errorf("Parse: invalid reference: %s", imgRef)
	}

	name, tag, digStr := splitReference(imgRef)

	if digStr != "" {
		dig, err := digest.Parse(digStr)
		if err != nil {
			return ImageReference{}, err
		}

		return ImageReference{
			Named:  name,
			Digest: dig.String(),
			Tag:    tag,
		}, nil
	}

	if conf.Digest != "" {
		return ImageReference{
			Named:  name,
			Digest: conf.Digest.String(),
			Tag:    tag,
		}, nil
	}

	return ImageReference{
		Named: name,
		Tag:   tag,
	}, nil
}

func getRepoInfo(ctx context.Context, ci ContainerdInterface) (repoDigests, repoTags []string) {

	refName, err := ci.GetImageName(ctx)
	if err != nil {
		return
	}
	cfg, err := ci.GetImageConfig(ctx)
	if err != nil {
		return
	}
	fmt.Printf("imageInspect name: %+v; \n", refName)
	reference, _ := Parse(ctx, refName, cfg)
	fmt.Printf("imageInspect referenece: %+v; \n", reference)
	if reference.Tag != "" {
		repoTags = append(repoTags, fmt.Sprintf(tagTemplate, reference.Named, reference.Tag))
	}
	if reference.Digest != "" {
		repoDigests = append(repoDigests, fmt.Sprintf(digestTemplate, reference.Named, reference.Digest))
	}
	return
}
