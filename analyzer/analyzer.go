package analyzer

import (
	"context"
	"encoding/json"

	digest "github.com/opencontainers/go-digest"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/extractor"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

const (
	SchemaVersion = 1
)

var (
	osAnalyzers      []OSAnalyzer
	pkgAnalyzers     []PkgAnalyzer
	libAnalyzers     []LibraryAnalyzer
	commandAnalyzers []CommandAnalyzer
	additionalFiles  []string

	// ErrUnknownOS occurs when unknown OS is analyzed.
	ErrUnknownOS = xerrors.New("Unknown OS")
	// ErrPkgAnalysis occurs when the analysis of packages is failed.
	ErrPkgAnalysis = xerrors.New("Failed to analyze packages")
	// ErrNoPkgsDetected occurs when the required files for an OS package manager are not detected
	ErrNoPkgsDetected = xerrors.New("No packages detected")
)

type OSAnalyzer interface {
	Analyze(extractor.FileMap) (types.OS, error)
	RequiredFiles() []string
}

type PkgAnalyzer interface {
	Analyze(extractor.FileMap) (map[types.FilePath][]types.Package, error)
	RequiredFiles() []string
}

type CommandAnalyzer interface {
	Analyze(types.OS, extractor.FileMap) ([]types.Package, error)
	RequiredFiles() []string
}

type LibraryAnalyzer interface {
	Name() string
	Analyze(extractor.FileMap) (map[types.FilePath][]godeptypes.Library, error)
	RequiredFiles() []string
}

func RegisterOSAnalyzer(analyzer OSAnalyzer) {
	osAnalyzers = append(osAnalyzers, analyzer)
}

func RegisterPkgAnalyzer(analyzer PkgAnalyzer) {
	pkgAnalyzers = append(pkgAnalyzers, analyzer)
}

func RegisterCommandAnalyzer(analyzer CommandAnalyzer) {
	commandAnalyzers = append(commandAnalyzers, analyzer)
}

func RegisterLibraryAnalyzer(analyzer LibraryAnalyzer) {
	libAnalyzers = append(libAnalyzers, analyzer)
}

func AddRequiredFilenames(filenames []string) {
	additionalFiles = append(additionalFiles, filenames...)
}

func RequiredFilenames() []string {
	var filenames []string
	filenames = append(filenames, additionalFiles...)
	for _, analyzer := range osAnalyzers {
		filenames = append(filenames, analyzer.RequiredFiles()...)
	}
	for _, analyzer := range pkgAnalyzers {
		filenames = append(filenames, analyzer.RequiredFiles()...)
	}
	for _, analyzer := range libAnalyzers {
		filenames = append(filenames, analyzer.RequiredFiles()...)
	}
	return filenames
}

type Config struct {
	Extractor extractor.Extractor
	Cache     cache.Cache
}

func New(ext extractor.Extractor, c cache.Cache) Config {
	return Config{Extractor: ext, Cache: c}
}

func (ac Config) Analyze(ctx context.Context) (types.ImageInfo, error) {
	imageID := ac.Extractor.ImageID()
	layerIDs := ac.Extractor.LayerIDs()
	missingLayers, err := ac.Cache.MissingLayers(layerIDs)
	if err != nil {
		return types.ImageInfo{}, err
	}
	if err := ac.analyzeLayers(ctx, missingLayers); err != nil {
		return types.ImageInfo{}, err
	}

	return types.ImageInfo{
		ID:       imageID,
		LayerIDs: layerIDs,
	}, nil
}

func (ac Config) analyzeLayers(ctx context.Context, layerIDs []string) error {
	done := make(chan struct{})
	errCh := make(chan error)

	for _, layerID := range layerIDs {
		go func(dig digest.Digest) {
			layerInfo, err := ac.analyzeLayer(ctx, dig)
			if err != nil {
				errCh <- xerrors.Errorf("failed to analyze layer: %w", dig, err)
				return
			}
			if err = ac.Cache.PutLayer(string(dig), layerInfo); err != nil {
				errCh <- xerrors.Errorf("failed to store layer in cache: %w", dig, err)
				return
			}
			done <- struct{}{}
		}(digest.Digest(layerID))
	}

	for range layerIDs {
		select {
		case <-done:
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return xerrors.Errorf("timeout: %w", ctx.Err())
		}
	}

	return nil
}

func (ac Config) analyzeLayer(ctx context.Context, dig digest.Digest) (types.LayerInfo, error) {
	files, opqDirs, whFiles, err := ac.Extractor.ExtractLayerFiles(ctx, dig, RequiredFilenames())
	if err != nil {
		return types.LayerInfo{}, err
	}

	os := GetOS(files)
	pkgs, err := GetPackages(files)
	if err != nil {
		return types.LayerInfo{}, err
	}
	apps, err := GetLibraries(files)
	if err != nil {
		return types.LayerInfo{}, err
	}

	layerInfo := types.LayerInfo{
		SchemaVersion: SchemaVersion,
		OS:            os,
		PackageInfos:  pkgs,
		Applications:  apps,
		OpaqueDirs:    opqDirs,
		WhiteoutFiles: whFiles,
	}
	return layerInfo, nil
}

func (ac Config) ApplyLayers(layerIDs []string) (types.ImageDetail, error) {
	var layers []types.LayerInfo
	for _, layerID := range layerIDs {
		b := ac.Cache.GetLayer(layerID)
		if b == nil {
			return types.ImageDetail{}, xerrors.Errorf("layer cache missing: %s", layerID)
		}
		var layer types.LayerInfo
		if err := json.Unmarshal(b, &layer); err != nil {
			return types.ImageDetail{}, err
		}
		layers = append(layers, layer)
	}

	mergedLayer, err := ac.Extractor.ApplyLayers(layers)
	if err != nil {
		return types.ImageDetail{}, err
	}

	if mergedLayer.OS == nil {
		return types.ImageDetail{}, ErrUnknownOS
	} else if mergedLayer.Packages == nil {
		return types.ImageDetail{}, ErrNoPkgsDetected
	}

	return mergedLayer, nil
}

func GetOS(filesMap extractor.FileMap) *types.OS {
	for _, analyzer := range osAnalyzers {
		os, err := analyzer.Analyze(filesMap)
		if err != nil {
			continue
		}
		return &os
	}
	return nil
}

func GetPackages(filesMap extractor.FileMap) ([]types.PackageInfo, error) {
	var results []types.PackageInfo
	for _, analyzer := range pkgAnalyzers {
		pkgMap, err := analyzer.Analyze(filesMap)

		// Differentiate between a package manager not being found and another error
		if err != nil && err == ErrNoPkgsDetected {
			continue
		} else if err != nil {
			return nil, xerrors.Errorf("failed to analyze packages: %w", err)
		}

		for filePath, pkgs := range pkgMap {
			results = append(results, types.PackageInfo{
				FilePath: string(filePath),
				Packages: pkgs,
			})
		}
		return results, nil
	}
	return nil, nil
}

func GetPackagesFromCommands(targetOS types.OS, filesMap extractor.FileMap) ([]types.Package, error) {
	for _, analyzer := range commandAnalyzers {
		pkgs, err := analyzer.Analyze(targetOS, filesMap)
		if err != nil {
			continue
		}
		return pkgs, nil
	}
	return nil, nil
}

func CheckPackage(pkg *types.Package) bool {
	return pkg.Name != "" && pkg.Version != ""
}

func GetLibraries(filesMap extractor.FileMap) ([]types.Application, error) {
	var results []types.Application
	for _, analyzer := range libAnalyzers {
		libMap, err := analyzer.Analyze(filesMap)
		if err != nil {
			return nil, xerrors.Errorf("failed to analyze libraries: %w", err)
		}

		for filePath, libs := range libMap {
			results = append(results, types.Application{
				Type:      analyzer.Name(),
				FilePath:  string(filePath),
				Libraries: libs,
			})
		}
	}
	return results, nil
}

func mergePkgs(pkgs, pkgsFromCommands []types.Package) []types.Package {
	uniqPkgs := map[string]struct{}{}
	for _, pkg := range pkgs {
		uniqPkgs[pkg.Name] = struct{}{}
	}
	for _, pkg := range pkgsFromCommands {
		if _, ok := uniqPkgs[pkg.Name]; ok {
			continue
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs
}
