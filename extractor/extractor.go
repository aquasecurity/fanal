package extractor

import (
	"context"

	digest "github.com/opencontainers/go-digest"
)

type FileMap map[string][]byte

type Extractor interface {
	ImageName() string
	ImageID() digest.Digest
	LayerIDs() []string
	ExtractLayerFiles(ctx context.Context, dig digest.Digest, filenames []string) (digest.Digest, FileMap, []string, []string, error)
}
