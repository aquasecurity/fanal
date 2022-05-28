package sbom

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/aquasecurity/fanal/handler"
	digest "github.com/opencontainers/go-digest"
	"github.com/package-url/packageurl-go"
	"golang.org/x/xerrors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
)

const (
	PropertyType            = "aquasecurity:trivy:Type"
	PropertySrcName         = "aquasecurity:trivy:SrcName"
	PropertySrcVersion      = "aquasecurity:trivy:SrcVersion"
	PropertySrcRelease      = "aquasecurity:trivy:SrcRelease"
	PropertySrcEpoch        = "aquasecurity:trivy:SrcEpoch"
	PropertyModularitylabel = "aquasecurity:trivy:Modularitylabel"
	PropertyFilePath        = "aquasecurity:trivy:FilePath"
)

type Artifact struct {
	filePath       string
	cache          cache.ArtifactCache
	analyzer       analyzer.AnalyzerGroup
	handlerManager handler.Manager

	artifactOption      artifact.Option
	configScannerOption config.ScannerOption
}

type TrivyBOM struct {
	cyclonedx.BOM
}

func (b TrivyBOM) BlobInfo() (types.BlobInfo, error) {
	blobInfo := types.BlobInfo{
		SchemaVersion: types.BlobJSONSchemaVersion, // TODO: use aquasecurity:trivy:SchemaVersion ??
	}
	if b.Components == nil {
		return blobInfo, nil
	}

	var osBOMRef string
	rootBOMRef := b.Metadata.Component.BOMRef
	apps := make(map[string]*types.Application)
	libs := make(map[string]*types.Package)

	for _, component := range *b.Components {
		switch component.Type {
		case cyclonedx.ComponentTypeOS:
			osBOMRef = component.BOMRef
			blobInfo.OS = parseOSComponent(component)
		case cyclonedx.ComponentTypeApplication:
			apps[component.BOMRef] = parseApplicationComponent(component)
		case cyclonedx.ComponentTypeLibrary:
			pkg, err := parseLibraryComponent(component)
			if err != nil {
				return types.BlobInfo{}, xerrors.Errorf("failed to parse package: %w", err)
			}
			if component.Properties == nil {
				libs[component.BOMRef] = pkg
				continue
			}
			if t := getProperty(component.Properties, PropertyType); t != "" {
				// If type property exists, it is Application.
				app := types.Application{
					Type:     t,
					FilePath: getProperty(component.Properties, PropertyFilePath),
				}
				app.Libraries = []types.Package{*pkg}
				apps[component.BOMRef] = &app
			} else {
				// If it isn't application component, it is library.
				libs[component.BOMRef] = pkg
			}
		}
	}

	if b.Dependencies == nil {
		return blobInfo, nil
	}
	for _, dep := range *b.Dependencies {
		if dep.Dependencies == nil {
			continue
		}

		var pkgInfo types.PackageInfo
		app, appOk := apps[dep.Ref]
		for _, d := range *dep.Dependencies {
			switch dep.Ref {
			case rootBOMRef:
				// root Ref depends on Aggregate libraries, Applications and Operating system.
				app, ok := apps[d.Ref]
				if !ok {
					continue
				}
				blobInfo.Applications = append(blobInfo.Applications, *app)
			case osBOMRef:
				// OperationsSystem Ref depends on os libraries.
				pkg, ok := libs[d.Ref]
				if !ok {
					continue
				}
				pkgInfo.Packages = append(pkgInfo.Packages, *pkg)
			default:
				// Other Ref dependencies application libraries.
				if !appOk {
					continue
				}
				pkg, ok := libs[d.Ref]
				if !ok {
					continue
				}
				app.Libraries = append(app.Libraries, *pkg)
			}

		}
		if len(pkgInfo.Packages) != 0 {
			blobInfo.PackageInfos = append(blobInfo.PackageInfos, pkgInfo)
		}
	}

	return blobInfo, nil
}

func NewArtifact(filePath string, c cache.ArtifactCache, opt artifact.Option) (artifact.Artifact, error) {
	handlerManager, err := handler.NewManager(opt)
	if err != nil {
		return nil, xerrors.Errorf("handler initialize error: %w", err)
	}

	return Artifact{
		filePath:       filepath.Clean(filePath),
		cache:          c,
		analyzer:       analyzer.NewAnalyzerGroup(opt.AnalyzerGroup, opt.DisabledAnalyzers),
		handlerManager: handlerManager,
		artifactOption: opt,
	}, nil
}

func (a Artifact) Inspect(_ context.Context) (types.ArtifactReference, error) {
	var err error
	bom := TrivyBOM{}

	extension := filepath.Ext(a.filePath)
	switch extension {
	case ".json":
		f, err := os.Open(a.filePath)
		if err != nil {
			return types.ArtifactReference{}, xerrors.Errorf("failed to open cycloneDX file error: %w", err)
		}
		defer f.Close()
		if err := json.NewDecoder(f).Decode(&bom); err != nil {
			return types.ArtifactReference{}, xerrors.Errorf("failed to json decode: %w", err)
		}
	case ".xml":
		// TODO: not supported yet
	default:
		return types.ArtifactReference{}, xerrors.Errorf("invalid cycloneDX format: %s", extension)
	}

	blobInfo, err := bom.BlobInfo()
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to get blob info: %w", err)
	}

	cacheKey, err := a.calcCacheKey(blobInfo)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to calculate a cache key: %w", err)
	}

	if err = a.cache.PutBlob(cacheKey, blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to store blob (%s) in cache: %w", cacheKey, err)
	}

	return types.ArtifactReference{
		Name:    bom.SerialNumber,
		Type:    types.ArtifactCycloneDX,
		ID:      cacheKey, // use a cache key as pseudo artifact ID
		BlobIDs: []string{cacheKey},
	}, nil
}

func (a Artifact) Clean(reference types.ArtifactReference) error {
	return a.cache.DeleteBlobs(reference.BlobIDs)
}

func (a Artifact) calcCacheKey(blobInfo types.BlobInfo) (string, error) {
	// calculate hash of JSON and use it as pseudo artifactID and blobID
	h := sha256.New()
	if err := json.NewEncoder(h).Encode(blobInfo); err != nil {
		return "", xerrors.Errorf("json error: %w", err)
	}

	d := digest.NewDigest(digest.SHA256, h)
	cacheKey, err := cache.CalcKey(d.String(), a.analyzer.AnalyzerVersions(), a.handlerManager.Versions(), a.artifactOption)
	if err != nil {
		return "", xerrors.Errorf("cache key: %w", err)
	}

	return cacheKey, nil
}

func purlToPackage(purl packageurl.PackageURL) types.Package {
	pkg := types.Package{
		Name:    purl.Name,
		Version: purl.Version,
	}
	if purl.Namespace == "" {
		return pkg
	}

	if purl.Type == packageurl.TypeMaven {
		purl.Namespace = strings.ReplaceAll(purl.Namespace, "/", ":")
	}
	pkg.Name = strings.Join([]string{purl.Namespace, purl.Name}, "/")

	return pkg
}

func getProperty(properties *[]cyclonedx.Property, key string) string {
	if properties == nil {
		return ""
	}

	for _, p := range *properties {
		if p.Name == key {
			return p.Value
		}
	}
	return ""
}

func parseOSComponent(component cyclonedx.Component) *types.OS {
	return &types.OS{
		Family: component.Name,
		Name:   component.Version,
	}
}

func parseApplicationComponent(component cyclonedx.Component) *types.Application {
	return &types.Application{
		Type:     getProperty(component.Properties, PropertyType),
		FilePath: component.Name,
	}
}

func parseLibraryComponent(component cyclonedx.Component) (*types.Package, error) {
	purl, err := packageurl.FromString(component.PackageURL)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse purl: %w", err)
	}
	pkg := purlToPackage(purl)
	for _, q := range purl.Qualifiers {
		switch q.Key {
		case "arch":
			pkg.Arch = q.Value
		}
	}
	for _, p := range *component.Properties {
		switch p.Name {
		case PropertySrcName:
			pkg.SrcName = p.Value
		case PropertySrcVersion:
			pkg.SrcVersion = p.Value
		case PropertySrcRelease:
			pkg.SrcRelease = p.Value
		case PropertySrcEpoch:
			pkg.SrcEpoch, err = strconv.Atoi(p.Value)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse source epoch: %w", err)
			}
		case PropertyModularitylabel:
			pkg.Modularitylabel = p.Value
		}
	}
	return &pkg, nil
}
