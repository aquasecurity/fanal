package extractor

import (
	"context"

	digest "github.com/opencontainers/go-digest"

	"github.com/aquasecurity/fanal/types"
)

type FileMap map[string][]byte

type Extractor interface {
	ImageID() digest.Digest
	LayerIDs() []string
	ApplyLayers(layers []types.LayerInfo) (mergedLayer types.ImageDetail, err error)
	//Extract(ctx context.Context, imageRef image.Reference, transports, filenames []string) (FileMap, error)
	ExtractLayerFiles(ctx context.Context, dig digest.Digest, filenames []string) (FileMap, []string, []string, error)
	//ExtractFiles(layer io.Reader, filenames []string) (FileMap, OPQDirs, error)
}
