package applier

import (
	"time"

	"github.com/aquasecurity/fanal/types"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/knqyf263/nested"
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

func containsPackage(e types.Package, s []types.Package) bool {
	for _, a := range s {
		if a.Name == e.Name && a.Version == e.Version && a.Release == e.Release {
			return true
		}
	}
	return false
}

func containsLibrary(e godeptypes.Library, s []types.LibraryInfo) bool {
	for _, a := range s {
		if e.Name == a.Library.Name && e.Version == a.Library.Version {
			return true
		}
	}
	return false
}

func lookupOriginLayerForPkg(pkg types.Package, layers []types.BlobInfo) (types.Layer, []string) {
	for i, layer := range layers {
		for _, info := range layer.PackageInfos {
			if containsPackage(pkg, info.Packages) {
				return types.Layer{
					Digest: layer.Digest,
					DiffID: layer.DiffID,
				}, lookupContentSets(i, layers)
			}
		}
	}
	return types.Layer{}, nil
}

// lookupContentSets looks up Red Hat content sets from all layers
func lookupContentSets(index int, layers []types.BlobInfo) []string {
	if len(layers[index].ContentSets) != 0 {
		return layers[index].ContentSets
	}

	// Base layer (layers[0]) is missing content sets
	//   - it needs to be shared from layers[1]
	if index == 0 {
		if len(layers) > 1 {
			return layers[1].ContentSets
		}
		return nil
	}

	// Customers layers build on top of Red Hat image are also missing content sets
	//   - it needs to be shared from the last Red Hat's layers which contains content sets
	for i := index - 1; i >= 1; i-- {
		if len(layers[i].ContentSets) != 0 {
			return layers[i].ContentSets
		}
	}
	return nil
}

func lookupOriginLayerForLib(filePath string, lib godeptypes.Library, layers []types.BlobInfo) types.Layer {
	for _, layer := range layers {
		for _, layerApp := range layer.Applications {
			if filePath != layerApp.FilePath {
				continue
			}
			if containsLibrary(lib, layerApp.Libraries) {
				return types.Layer{
					Digest: layer.Digest,
					DiffID: layer.DiffID,
				}
			}
		}
	}
	return types.Layer{}
}

func ApplyLayers(layers []types.BlobInfo) types.ArtifactDetail {
	sep := "/"
	nestedMap := nested.Nested{}
	var mergedLayer types.ArtifactDetail

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

	_ = nestedMap.Walk(func(keys []string, value interface{}) error {
		switch v := value.(type) {
		case types.PackageInfo:
			mergedLayer.Packages = append(mergedLayer.Packages, v.Packages...)
		case types.Application:
			mergedLayer.Applications = append(mergedLayer.Applications, v)
		}
		return nil
	})

	for i, pkg := range mergedLayer.Packages {
		originLayer, contentSets := lookupOriginLayerForPkg(pkg, layers)
		mergedLayer.Packages[i].Layer = originLayer
		mergedLayer.Packages[i].ContentSets = contentSets
	}

	for _, app := range mergedLayer.Applications {
		for i, libInfo := range app.Libraries {
			app.Libraries[i].Layer = lookupOriginLayerForLib(app.FilePath, libInfo.Library, layers)
		}
	}

	return mergedLayer
}
