package extractor

import (
	"context"

	digest "github.com/opencontainers/go-digest"
)

type FileMap map[string][]byte

type Extractor interface {
	ImageName() (imageName string)
	ImageID() (imageDigest digest.Digest)
	LayerIDs() (layerIDs []string)
	ExtractLayerFiles(ctx context.Context, dig digest.Digest, filenames []string) (decompressedLayerId digest.Digest, files FileMap, opqDirs []string, whFiles []string, err error)
}
