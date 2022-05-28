package sbom

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/aquasecurity/fanal/analyzer/secret"
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
	PropertyType  = "aquasecurity:trivy:Type"
	PropertyClass = "aquasecurity:trivy:Class"

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

func purlToPackage(purl packageurl.PackageURL) types.Package {
	pkg := types.Package{
		Name:    purl.Name,
		Version: purl.Version,
	}
	if purl.Namespace == "" {
		return pkg
	}

	switch purl.Type {
	case packageurl.TypePyPi:
		// TODO:
		pkg.Name = strings.Join([]string{purl.Namespace, purl.Name}, "/")
	case packageurl.TypeMaven:
		pkg.Name = strings.Join([]string{strings.ReplaceAll(purl.Namespace, "/", ":"), purl.Name}, "/")
	default:
		pkg.Name = strings.Join([]string{purl.Namespace, purl.Name}, "/")
	}
	return pkg
}

func (b TrivyBOM) BlobInfo() (types.BlobInfo, error) {
	blobInfo := types.BlobInfo{
		SchemaVersion: types.BlobJSONSchemaVersion, // TODO: use aquasecurity:trivy:SchemaVersion ??
	}

	apps := make(map[string]*types.Application)
	libs := make(map[string]*types.Package)
	rootBomRef := b.Metadata.Component.BOMRef
	var osBomRef string
	if b.Components == nil {
		return types.BlobInfo{}, nil
	}

	for _, component := range *b.Components {
		switch component.Type {
		case cyclonedx.ComponentTypeOS:
			blobInfo.OS = &types.OS{
				Family: component.Name,
				Name:   component.Version,
			}
			osBomRef = component.BOMRef
		case cyclonedx.ComponentTypeApplication:
			app := types.Application{}
			if component.Properties != nil {
				for _, p := range *component.Properties {
					if p.Name == PropertyType {
						app.Type = p.Value
					}
				}
			}
			app.FilePath = component.Name
			apps[component.BOMRef] = &app
		case cyclonedx.ComponentTypeLibrary:
			purl, err := packageurl.FromString(component.PackageURL)
			if err != nil {
				return types.BlobInfo{}, xerrors.Errorf("failed to parse purl: %w", err)
			}
			pkg := purlToPackage(purl)
			for _, q := range purl.Qualifiers {
				switch q.Key {
				case "arch":
					pkg.Arch = q.Value
				}
			}

			if component.Properties != nil {
				app := types.Application{}
				for _, p := range *component.Properties {
					if p.Name == PropertyFilePath {
						// Library containing FilePath is treated as an Application.
						app.FilePath = p.Value
					}
					if p.Name == PropertyType {
						app.Type = p.Value
					}
				}
				if app.Type != "" {
					app.Libraries = []types.Package{pkg}
					apps[component.BOMRef] = &app
					// probably return
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
							return types.BlobInfo{}, xerrors.Errorf("failed to parse source epoch: %w", err)
						}
					case PropertyModularitylabel:
						pkg.Modularitylabel = p.Value
					}
				}
			}
			libs[component.BOMRef] = &pkg
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
			case rootBomRef: // Aggregate libraries component, Applications component, OS Component
				app, ok := apps[d.Ref]
				if !ok {
					continue
				}
				blobInfo.Applications = append(blobInfo.Applications, *app)
			case osBomRef: // os libraries
				pkg, ok := libs[d.Ref]
				if !ok {
					continue
				}
				pkgInfo.Packages = append(pkgInfo.Packages, *pkg)
			default:
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
	// Register config analyzers
	if err := config.RegisterConfigAnalyzers(opt.MisconfScannerOption.FilePatterns); err != nil {
		return nil, xerrors.Errorf("config analyzer error: %w", err)
	}

	handlerManager, err := handler.NewManager(opt)
	if err != nil {
		return nil, xerrors.Errorf("handler initialize error: %w", err)
	}

	// Register secret analyzer
	if err = secret.RegisterSecretAnalyzer(opt.SecretScannerOption); err != nil {
		return nil, xerrors.Errorf("secret scanner error: %w", err)
	}

	return Artifact{
		filePath:       filepath.Clean(filePath),
		cache:          c,
		analyzer:       analyzer.NewAnalyzerGroup(opt.AnalyzerGroup, opt.DisabledAnalyzers),
		handlerManager: handlerManager,
		artifactOption: opt,
	}, nil
}

func (a Artifact) Inspect(ctx context.Context) (types.ArtifactReference, error) {
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

	// get hostname
	var hostName string
	// TODO: get Name for artifact

	return types.ArtifactReference{
		Name:    hostName,
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
