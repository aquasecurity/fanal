package extractor

import (
	"context"
	"io"

	"github.com/opencontainers/go-digest"

	"github.com/aquasecurity/fanal/extractor/image"
)

type FileMap map[string][]byte
type OPQDirs []string

type Extractor interface {
	LayerInfos() ([]string, error)
	Extract(ctx context.Context, imageRef image.Reference, transports, filenames []string) (FileMap, error)
	ExtractLayerFiles(ctx context.Context, dig digest.Digest, filenames []string) (FileMap, OPQDirs, error)
	ExtractFiles(layer io.Reader, filenames []string) (FileMap, OPQDirs, error)
}
