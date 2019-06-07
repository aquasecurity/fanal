package docker

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"

	"github.com/knqyf263/fanal/extractor"
	"github.com/knqyf263/fanal/extractor/docker/token/ecr"
	"github.com/knqyf263/fanal/extractor/docker/token/gcr"
	"github.com/knqyf263/fanal/types"

	"github.com/docker/distribution/manifest/schema2"
	"github.com/docker/docker/client"
	"github.com/genuinetools/reg/registry"
	"github.com/knqyf263/fanal/cache"
	"github.com/knqyf263/nested"
	"golang.org/x/xerrors"
)

const (
	opq string = ".wh..wh..opq"
	wh  string = ".wh."
)

type manifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

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
	ID      digest.Digest
	Content io.ReadCloser
}

type opqDirs []string

type DockerExtractor struct {
	Option types.DockerOption
}

func NewDockerExtractor(option types.DockerOption) DockerExtractor {
	RegisterRegistry(&gcr.GCR{})
	RegisterRegistry(&ecr.ECR{})
	return DockerExtractor{Option: option}
}

func applyLayers(layerIDs []string, filesInLayers map[string]extractor.FileMap, opqInLayers map[string]opqDirs) (extractor.FileMap, error) {
	sep := "/"
	nestedMap := nested.Nested{}
	for _, layerID := range layerIDs {
		layerID := strings.Split(layerID, sep)[0]
		for _, opqDir := range opqInLayers[layerID] {
			nestedMap.DeleteByString(opqDir, sep)
		}

		for filePath, content := range filesInLayers[layerID] {
			fileName := filepath.Base(filePath)
			fileDir := filepath.Dir(filePath)
			switch {
			case strings.HasPrefix(fileName, wh):
				fname := strings.TrimPrefix(fileName, wh)
				fpath := filepath.Join(fileDir, fname)
				nestedMap.DeleteByString(fpath, sep)
			default:
				nestedMap.SetByString(filePath, sep, content)
			}
		}
	}

	fileMap := extractor.FileMap{}
	walkFn := func(keys []string, value interface{}) error {
		content, ok := value.(extractor.FileData)
		if !ok {
			return nil
		}
		path := strings.Join(keys, "/")
		fileMap[path] = content
		return nil
	}
	if err := nestedMap.Walk(walkFn); err != nil {
		return nil, xerrors.Errorf("failed to walk nested map: %w", err)
	}

	return fileMap, nil

}

func (d DockerExtractor) createRegistryClient(ctx context.Context, domain string) (*registry.Registry, error) {
	auth, err := GetToken(ctx, domain, d.Option)
	if err != nil {
		return nil, xerrors.Errorf("failed to get auth config: %w", err)
	}

	// Prevent non-ssl unless explicitly forced
	if !d.Option.NonSSL && strings.HasPrefix(auth.ServerAddress, "http:") {
		return nil, xerrors.New("attempted to use insecure protocol! Use force-non-ssl option to force")
	}

	// Create the registry client.
	return registry.New(ctx, auth, registry.Opt{
		Domain:   domain,
		Insecure: d.Option.Insecure,
		Debug:    d.Option.Debug,
		SkipPing: d.Option.SkipPing,
		NonSSL:   d.Option.NonSSL,
		Timeout:  d.Option.Timeout,
	})
}

func (d DockerExtractor) SaveLocalImage(ctx context.Context, imageName string) (io.Reader, error) {
	var err error
	r := cache.Get(imageName)
	if r == nil {
		// Save the image
		r, err = d.saveLocalImage(ctx, imageName)
		if err != nil {
			return nil, err
		}
		r, err = cache.Set(imageName, r)
		if err != nil {
			log.Print(err)
		}
	}

	return r, nil
}

func (d DockerExtractor) saveLocalImage(ctx context.Context, imageName string) (io.ReadCloser, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, xerrors.New("error in docker NewClient")
	}

	r, err := cli.ImageSave(ctx, []string{imageName})
	if err != nil {
		return nil, xerrors.New("error in docker image save")
	}
	return r, nil
}

func (d DockerExtractor) Extract(ctx context.Context, imageName string, filenames []string, permissions []os.FileMode) (extractor.FileMap, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.Option.Timeout)
	defer cancel()

	image, err := registry.ParseImage(imageName)
	if err != nil {
		return nil, err
	}
	r, err := d.createRegistryClient(ctx, image.Domain)
	if err != nil {
		return nil, err
	}

	// Get the v2 manifest.
	manifest, err := r.Manifest(ctx, image.Path, image.Reference())
	if err != nil {
		return nil, err
	}
	m, ok := manifest.(*schema2.DeserializedManifest)
	if !ok {
		return nil, xerrors.New("invalid manifest")
	}

	ch := make(chan layer)
	errCh := make(chan error)
	layerIDs := []string{}
	for _, ref := range m.Manifest.Layers {
		layerIDs = append(layerIDs, string(ref.Digest))
		go func(d digest.Digest) {
			// Use cache
			rc := cache.Get(string(d))
			if rc == nil {
				// Download the layer.
				rc, err = r.DownloadLayer(ctx, image.Path, d)
				if err != nil {
					errCh <- xerrors.Errorf("failed to download the layer(%s): %w", d, err)
					return
				}
				rc, err = cache.Set(string(d), rc)
				if err != nil {
					log.Print(err)
				}
			}
			gzipReader, err := gzip.NewReader(rc)
			if err != nil {
				errCh <- xerrors.Errorf("invalid gzip: %w", err)
				return
			}
			ch <- layer{ID: d, Content: gzipReader}
		}(ref.Digest)
	}

	filesInLayers := make(map[string]extractor.FileMap)
	opqInLayers := make(map[string]opqDirs)
	for i := 0; i < len(m.Manifest.Layers); i++ {
		var l layer
		select {
		case l = <-ch:
		case err := <-errCh:
			return nil, err
		case <-ctx.Done():
			return nil, xerrors.Errorf("timeout: %w", ctx.Err())
		}
		files, opqDirs, err := d.ExtractFiles(l.Content, filenames, permissions)
		if err != nil {
			return nil, err
		}

		// add checked file once
		checkedFilenames := []string{}
		for filename, _ := range files {
			checkedFilenames = append(checkedFilenames, filename)
		}
		filenames = append(filenames, checkedFilenames...)
		layerID := string(l.ID)
		filesInLayers[layerID] = files
		opqInLayers[layerID] = opqDirs
	}

	fileMap, err := applyLayers(layerIDs, filesInLayers, opqInLayers)
	if err != nil {
		return nil, xerrors.Errorf("failed to apply layers: %w", err)
	}

	// download config file
	rc, err := r.DownloadLayer(ctx, image.Path, m.Manifest.Config.Digest)
	if err != nil {
		return nil, xerrors.Errorf("error in layer download: %w", err)
	}
	config, err := ioutil.ReadAll(rc)
	if err != nil {
		return nil, xerrors.Errorf("failed to decode config JSON: %w", err)
	}

	// special file for command analyzer
	fileMap["/config"] = extractor.FileData{Body: config, FileMode: os.ModePerm}

	return fileMap, nil
}

func (d DockerExtractor) ExtractFromFile(ctx context.Context, r io.Reader, filenames []string, permissions []os.FileMode) (extractor.FileMap, error) {
	manifests := make([]manifest, 0)
	filesInLayers := map[string]extractor.FileMap{}
	tmpJSONs := extractor.FileMap{}
	opqInLayers := make(map[string]opqDirs)

	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, extractor.ErrCouldNotExtract
		}
		switch {
		case header.Name == "manifest.json":
			if err := json.NewDecoder(tr).Decode(&manifests); err != nil {
				return nil, err
			}
		case strings.HasSuffix(header.Name, ".json"):
			// save all JSON temporarily for config JSON
			data, err := ioutil.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			tmpJSONs[header.Name] = extractor.FileData{Body: data, FileMode: os.ModePerm}

		case strings.HasSuffix(header.Name, ".tar"):
			layerID := filepath.Base(filepath.Dir(header.Name))
			files, opqDirs, err := d.ExtractFiles(tr, filenames, permissions)
			if err != nil {
				return nil, err
			}

			// add checked file once
			checkedFilenames := []string{}
			for filename, _ := range files {
				checkedFilenames = append(checkedFilenames, filename)
			}
			filenames = append(filenames, checkedFilenames...)
			filesInLayers[layerID] = files
			opqInLayers[layerID] = opqDirs
		default:
		}
	}

	if len(manifests) == 0 {
		return nil, xerrors.New("Invalid image")
	}

	fileMap, err := applyLayers(manifests[0].Layers, filesInLayers, opqInLayers)
	if err != nil {
		return nil, err
	}

	// special file for command analyzer
	fileMap["/config"] = tmpJSONs[manifests[0].Config]

	return fileMap, nil
}

func (d DockerExtractor) ExtractFiles(layer io.Reader, filenames []string, permissions []os.FileMode) (extractor.FileMap, opqDirs, error) {
	data := make(map[string]extractor.FileData)
	opqDirs := opqDirs{}

	tr := tar.NewReader(layer)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return data, nil, extractor.ErrCouldNotExtract
		}

		filePath := hdr.Name
		filePath = filepath.Clean(filePath)
		fileName := filepath.Base(filePath)
		fi := hdr.FileInfo()
		fileMode := fi.Mode()

		// e.g. etc/.wh..wh..opq
		if opq == fileName {
			opqDirs = append(opqDirs, filepath.Dir(filePath))
			continue
		}

		// Determine if we should extract the element
		extract := false
		for _, s := range filenames {
			if s == filePath || s == fileName || strings.HasPrefix(fileName, wh) {
				extract = true
				break
			}
		}

		if extract == false {
			for _, p := range permissions {
				if fileMode&p != 0 {
					extract = true
					break
				}
			}
		}

		if !extract {
			continue
		}

		if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink || hdr.Typeflag == tar.TypeReg {
			d, err := ioutil.ReadAll(tr)
			if err != nil {
				return nil, nil, xerrors.Errorf("failed to read file: %w", err)
			}
			data[filePath] = extractor.FileData{
				Body:     d,
				FileMode: fileMode,
			}
		}
	}

	return data, opqDirs, nil

}
