package applier

import (
	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
	"golang.org/x/xerrors"
)

type Applier struct {
	cache cache.LocalArtifactCache
}

func NewApplier(c cache.LocalArtifactCache) Applier {
	return Applier{cache: c}
}

func (a Applier) GetCache() types.CacheType {
	return a.cache.Type()
}

func (a Applier) ApplyLayers(imageID string, layerKeys []string) (types.ArtifactDetail, error) {
	var layers []types.BlobInfo
	for _, blobID := range layerKeys {
		blob, _ := a.cache.GetBlob(blobID)
		if blob.SchemaVersion == 0 {
			return types.ArtifactDetail{}, xerrors.Errorf("layer cache missing: %s", blobID)
		}
		layers = append(layers, blob)
	}

	mergedLayer := ApplyLayers(layers)
	if mergedLayer.OS == nil {
		return mergedLayer, analyzer.ErrUnknownOS // send back package and apps info regardless
	} else if mergedLayer.Packages == nil {
		return mergedLayer, analyzer.ErrNoPkgsDetected // send back package and apps info regardless
	}

	imageInfo, _ := a.cache.GetArtifact(imageID)
	mergedLayer.HistoryPackages = imageInfo.HistoryPackages

	return mergedLayer, nil
}
