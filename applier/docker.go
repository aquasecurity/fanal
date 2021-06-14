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

func lookupOriginLayerForPkg(pkg types.Package, layers []types.BlobInfo) (string, string) {
	for _, layer := range layers {
		for _, info := range layer.PackageInfos {
			if containsPackage(pkg, info.Packages) {
				return layer.Digest, layer.DiffID
			}
		}
	}
	return "", ""
}

func lookupOriginLayerForLib(filePath string, lib godeptypes.Library, layers []types.BlobInfo) (string, string) {
	for _, layer := range layers {
		for _, layerApp := range layer.Applications {
			if filePath != layerApp.FilePath {
				continue
			}
			if containsLibrary(lib, layerApp.Libraries) {
				return layer.Digest, layer.DiffID
			}
		}
	}
	return "", ""
}

func ApplyLayers(layers []types.BlobInfo) types.ArtifactDetail {
	sep := "/"
	nestedMap := nested.Nested{}
	var mergedLayer types.ArtifactDetail
	analyzerNestedMap := map[string]map[string]nested.Nested{}
	for _, layer := range layers {
		mergedLayer.Size += layer.Size
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
		for _, config := range layer.Misconfigurations {
			config.Layer = types.Layer{
				Digest: layer.Digest,
				DiffID: layer.DiffID,
			}
			nestedMap.SetByString(config.FilePath, sep, config)
		}
		for cache, analyzerResources := range layer.CustomResources {
			if _, ok := analyzerNestedMap[cache]; !ok {
				analyzerNestedMap[cache] = map[string]nested.Nested{}
			}
			for analyzer, resources := range analyzerResources {
				if _, ok := analyzerNestedMap[cache][analyzer]; !ok {
					// Create 1 nested map for each analyzer of cache
					analyzerNestedMap[cache][analyzer] = nested.Nested{}
				}
				for _, opqDir := range layer.OpaqueDirs {
					_ = analyzerNestedMap[cache][analyzer].DeleteByString(opqDir, sep)
				}
				for _, whFile := range layer.WhiteoutFiles {
					_ = analyzerNestedMap[cache][analyzer].DeleteByString(whFile, sep)
				}
				for _, info := range resources {
					analyzerNestedMap[cache][analyzer].SetByString(info.FilePath, sep, info)
				}
			}
		}
	}

	_ = nestedMap.Walk(func(keys []string, value interface{}) error {
		switch v := value.(type) {
		case types.PackageInfo:
			mergedLayer.Packages = append(mergedLayer.Packages, v.Packages...)
		case types.Application:
			mergedLayer.Applications = append(mergedLayer.Applications, v)
		case types.Misconfiguration:
			mergedLayer.Misconfigurations = append(mergedLayer.Misconfigurations, v)
		}
		return nil
	})

	for cache, cacheNestedMap := range analyzerNestedMap {
		if mergedLayer.CustomResources == nil {
			mergedLayer.CustomResources = map[string]types.AnalyzerResources{}
		}
		mergedLayer.CustomResources[cache] = types.AnalyzerResources{}
		for analyzer, nestedMap := range cacheNestedMap {
			if _, ok := mergedLayer.CustomResources[cache][analyzer]; !ok {
				mergedLayer.CustomResources[cache][analyzer] = []types.CustomResource{}
			}
			_ = nestedMap.Walk(func(keys []string, value interface{}) error {
				switch v := value.(type) {
				case types.CustomResource:
					if data, ok := mergedLayer.CustomResources[cache][analyzer]; ok {
						mergedLayer.CustomResources[cache][analyzer] = append(data, v)
					} else {
						mergedLayer.CustomResources[cache][analyzer] = []types.CustomResource{v}
					}
				}
				return nil
			})
		}

	}

	for i, pkg := range mergedLayer.Packages {
		originLayerDigest, originLayerDiffID := lookupOriginLayerForPkg(pkg, layers)
		mergedLayer.Packages[i].Layer = types.Layer{
			Digest: originLayerDigest,
			DiffID: originLayerDiffID,
		}
	}

	for _, app := range mergedLayer.Applications {
		for i, libInfo := range app.Libraries {
			originLayerDigest, originLayerDiffID := lookupOriginLayerForLib(app.FilePath, libInfo.Library, layers)
			app.Libraries[i].Layer = types.Layer{
				Digest: originLayerDigest,
				DiffID: originLayerDiffID,
			}
		}
	}

	return mergedLayer
}
