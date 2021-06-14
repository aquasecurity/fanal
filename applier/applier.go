package applier

import (
	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
	"golang.org/x/xerrors"
)

type Applier struct {
	cache []cache.LocalArtifactCache
}

func NewApplier(c cache.LocalArtifactCache) Applier {
	return Applier{cache: []cache.LocalArtifactCache{c}}
}

func NewApplierMultiCache(c []cache.LocalArtifactCache) Applier {
	return Applier{cache: c}
}

func (a Applier) mergeCacheLayers(layers map[types.CacheType]types.BlobInfo) types.BlobInfo {
	base := layers[types.BuiltInCache]
	for cache, layer := range layers {
		if cache == types.BuiltInCache {
			continue
		}
		if base.CustomResources == nil {
			base.CustomResources = map[string]types.AnalyzerResources{}
		}
		base.CustomResources[string(cache)] = layer.CustomResources[string(cache)]
	}
	return base
}

func (a Applier) ApplyLayers(imageID string, diffIDs []string) (types.ArtifactDetail, error) {
	var layers []types.BlobInfo
	for _, diffID := range diffIDs {
		// combining a1,b1,c1 = abc1
		blobsInCache := map[types.CacheType]types.BlobInfo{}
		for i := range a.cache {
			blob, _ := a.cache[i].GetBlob(diffID)
			if blob.SchemaVersion == 0 {
				return types.ArtifactDetail{}, xerrors.Errorf("layer cache missing: %s", diffID)
			}
			blobsInCache[a.cache[i].Type()] = blob
		}

		layers = append(layers, a.mergeCacheLayers(blobsInCache))
	}
	// layers = [abc1, abc2, abc3]
	mergedLayer := ApplyLayers(layers)
	if mergedLayer.OS == nil {
		return mergedLayer, analyzer.ErrUnknownOS // send back package and apps info regardless
	} else if mergedLayer.Packages == nil {
		return mergedLayer, analyzer.ErrNoPkgsDetected // send back package and apps info regardless
	}

	for i := range a.cache {
		if a.cache[i].Type() == types.BuiltInCache {
			imageInfo, _ := a.cache[i].GetArtifact(imageID)
			mergedLayer.HistoryPackages = imageInfo.HistoryPackages
		}
	}

	return mergedLayer, nil
}
