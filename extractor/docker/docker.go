package docker

import (
	"archive/tar"
	"context"
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquasecurity/fanal/extractor/image/token/ecr"
	"github.com/aquasecurity/fanal/extractor/image/token/gcr"
	digest "github.com/opencontainers/go-digest"

	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/extractor/image"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"github.com/knqyf263/nested"
	"golang.org/x/xerrors"
)

const (
	opq string = ".wh..wh..opq"
	wh  string = ".wh."
)

type Config struct {
	ContainerConfig containerConfig `json:"container_config"`
	History         []History
}

type containerConfig struct {
	Env []string
}

type History struct {
	Created   time.Time
	CreatedBy string `json:"created_by"`
}

type layer struct {
	id      digest.Digest
	content io.ReadCloser
	cleanup func()
}

type Extractor struct {
	option types.DockerOption
	image  image.Image
}

func init() {
	image.RegisterRegistry(&gcr.GCR{})
	image.RegisterRegistry(&ecr.ECR{})
}

func NewDockerExtractor(ctx context.Context, imageName string, option types.DockerOption) (Extractor, error) {
	ref := image.Reference{Name: imageName, IsFile: false}
	transports := []string{"docker-daemon:", "docker://"}
	return newDockerExtractor(ctx, ref, transports, option)
}

func NewDockerTarExtractor(ctx context.Context, fileName string, option types.DockerOption) (Extractor, error) {
	ref := image.Reference{Name: fileName, IsFile: true}
	transports := []string{"docker-archive:"}
	return newDockerExtractor(ctx, ref, transports, option)
}

func newDockerExtractor(ctx context.Context, imgRef image.Reference, transports []string,
	option types.DockerOption) (Extractor, error) {
	ctx, cancel := context.WithTimeout(ctx, option.Timeout)
	defer cancel()

	img, err := image.NewImage(ctx, imgRef, transports, option)
	if err != nil {
		return Extractor{}, xerrors.Errorf("unable to initialize a image struct: %w", err)
	}

	return Extractor{
		option: option,
		image:  img,
	}, nil
}

func (d Extractor) ApplyLayers(layers []types.LayerInfo) (types.ImageDetail, error) {
	sep := "/"
	nestedMap := nested.Nested{}
	var mergedLayer types.ImageDetail

	for _, layer := range layers {
		for _, opqDir := range layer.OpaqueDirs {
			_ = nestedMap.DeleteByString(opqDir, sep)
		}
		for _, whFile := range layer.WhiteoutFiles {
			_ = nestedMap.DeleteByString(whFile, sep)
		}

		if layer.OS != nil {
			mergedLayer.OS = layer.OS
		}

		for _, pkgInfo := range layer.PackageInfos {
			nestedMap.SetByString(pkgInfo.FilePath, sep, pkgInfo)
		}
		for _, app := range layer.Applications {
			nestedMap.SetByString(app.FilePath, sep, app)
		}
	}

	walkFn := func(keys []string, value interface{}) error {
		switch v := value.(type) {
		case types.PackageInfo:
			mergedLayer.Packages = append(mergedLayer.Packages, v.Packages...)
		case types.Application:
			mergedLayer.Applications = append(mergedLayer.Applications, v)
		}
		return nil
	}
	if err := nestedMap.Walk(walkFn); err != nil {
		return types.ImageDetail{}, xerrors.Errorf("failed to walk nested map: %w", err)
	}
	return mergedLayer, nil
}

func (d Extractor) LayerIDs() []string {
	return d.image.LayerIDs()
}

func (d Extractor) ImageID() digest.Digest {
	return d.image.ConfigInfo().Digest
}

func (d Extractor) ExtractLayerFiles(ctx context.Context, dig digest.Digest, filenames []string) (
	extractor.FileMap, []string, []string, error) {
	img, err := d.image.GetBlob(ctx, dig)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("failed to get a blob: %w", err)
	}
	defer img.Close()

	files, opqDirs, whFiles, err := d.extractFiles(img, filenames)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("failed to extract files: %w", err)
	}

	return files, opqDirs, whFiles, nil
}

func (d Extractor) extractFiles(layer io.Reader, filenames []string) (extractor.FileMap, []string, []string, error) {
	data := make(map[string][]byte)
	var opqDirs, whFiles []string

	tr := tar.NewReader(layer)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return data, nil, nil, xerrors.Errorf("failed to extract the archive: %w", err)
		}

		filePath := hdr.Name
		filePath = strings.TrimLeft(filepath.Clean(filePath), "/")
		fileDir, fileName := filepath.Split(filePath)

		// e.g. etc/.wh..wh..opq
		if opq == fileName {
			opqDirs = append(opqDirs, fileDir)
			continue
		}
		// etc/.wh.hostname
		if strings.HasPrefix(fileName, wh) {
			name := strings.TrimPrefix(fileName, wh)
			fpath := filepath.Join(fileDir, name)
			whFiles = append(whFiles, fpath)
			continue
		}

		if d.isIgnored(filePath) {
			continue
		}

		// Determine if we should extract the element
		extract := false
		for _, s := range filenames {
			// extract all files in target directory if last char is "/"(Separator)
			if s[len(s)-1] == '/' {
				if filepath.Clean(s) == filepath.Dir(filePath) {
					extract = true
					break
				}
			}

			if s == filePath || s == fileName {
				extract = true
				break
			}
		}

		if !extract {
			continue
		}

		if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink || hdr.Typeflag == tar.TypeReg {
			d, err := ioutil.ReadAll(tr)
			if err != nil {
				return nil, nil, nil, xerrors.Errorf("failed to read file: %w", err)
			}
			data[filePath] = d
		}
	}

	return data, opqDirs, whFiles, nil
}

func (d Extractor) isIgnored(filePath string) bool {
	for _, path := range strings.Split(filePath, utils.PathSeparator) {
		if utils.StringInSlice(path, library.IgnoreDirs) {
			return true
		}
	}
	return false
}
