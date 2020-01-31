package analyzer

import (
	"context"

	"github.com/opencontainers/go-digest"

	"github.com/aquasecurity/fanal/cache"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/extractor/image"
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

type Config struct {
	Extractor extractor.Extractor
	Cache     cache.Cache
}

type OSAnalyzer interface {
	Analyze(extractor.FileMap) (OS, error)
	RequiredFiles() []string
}

type PkgAnalyzer interface {
	Analyze(extractor.FileMap) ([]Package, error)
	RequiredFiles() []string
}

type CommandAnalyzer interface {
	Analyze(OS, extractor.FileMap) ([]Package, error)
	RequiredFiles() []string
}

type FilePath string

type LibraryAnalyzer interface {
	Name() string
	Analyze(extractor.FileMap) (map[FilePath][]godeptypes.Library, error)
	RequiredFiles() []string
}

type OS struct {
	Name   string
	Family string
}

type Package struct {
	Name       string
	Version    string
	Release    string
	Epoch      int
	Arch       string
	SrcName    string
	SrcVersion string
	SrcRelease string
	SrcEpoch   int
}

type SrcPackage struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	BinaryNames []string `json:"binaryNames"`
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
	filenames := []string{}
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

func (ac Config) Analyze(ctx context.Context, imageName string) ([]string, error) {
	//transports := []string{"docker-daemon:", "docker://"}
	//ref := image.Reference{Name: imageName, IsFile: false}
	layerIDs, err := ac.Extractor.LayerInfos()
	if err != nil {
		return nil, err
	}

	missingLayers := ac.Cache.MissingKeys(layerIDs)
	if err = ac.analyzeLayers(ctx, missingLayers); err != nil {
		return nil, err
	}

	//fileMap, err = ac.Extractor.Extract(ctx, ref, transports, RequiredFilenames())
	//if err != nil {
	//	return nil, xerrors.Errorf("failed to extract files: %w", err)
	//}
	return layerIDs, nil
}

type LayerInfo struct {
	SchemaVersion int
	OS            OS
	Packages      []Package
	Applications  []Application
	OpaqueDirs    extractor.OPQDirs
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
			if err = ac.Cache.Set(string(dig), layerInfo); err != nil {
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

func (ac Config) analyzeLayer(ctx context.Context, dig digest.Digest) (LayerInfo, error) {
	files, opqDirs, err := ac.Extractor.ExtractLayerFiles(ctx, dig, RequiredFilenames())
	if err != nil {
		//errCh <- xerrors.Errorf("failed to get a blob: %w", err)
		return LayerInfo{}, err
	}

	os, err := GetOS(files)
	if err != nil {
		return LayerInfo{}, err
	}
	pkgs, err := GetPackages(files)
	if err != nil {
		return LayerInfo{}, err
	}
	pkgsFromCommands, err := GetPackagesFromCommands(os, files)
	if err != nil {
		return LayerInfo{}, err
	}
	mergedPkgs := mergePkgs(pkgs, pkgsFromCommands)

	apps, err := GetLibraries(files)

	layerInfo := LayerInfo{
		SchemaVersion: SchemaVersion,
		OS:            os,
		Packages:      mergedPkgs,
		Applications:  apps,
		OpaqueDirs:    opqDirs,
	}
	return layerInfo, nil
}

func (ac Config) AnalyzeFile(ctx context.Context, filePath string) (fileMap extractor.FileMap, err error) {
	transports := []string{"docker-archive:"}
	ref := image.Reference{Name: filePath, IsFile: true}
	fileMap, err = ac.Extractor.Extract(ctx, ref, transports, RequiredFilenames())
	if err != nil {
		return nil, xerrors.Errorf("failed to extract files: %w", err)
	}
	return fileMap, nil
}

func GetOS(filesMap extractor.FileMap) (OS, error) {
	for _, analyzer := range osAnalyzers {
		os, err := analyzer.Analyze(filesMap)
		if err != nil {
			continue
		}
		return os, nil
	}
	return OS{}, ErrUnknownOS

}

func GetPackages(filesMap extractor.FileMap) ([]Package, error) {
	for _, analyzer := range pkgAnalyzers {
		pkgs, err := analyzer.Analyze(filesMap)

		// Differentiate between a package manager not being found and another error
		if err != nil && err == ErrNoPkgsDetected {
			continue
		} else if err != nil {
			return nil, xerrors.Errorf("failed to analyze packages: %w", err)
		}
		return pkgs, nil
	}
	return nil, ErrPkgAnalysis
}

func GetPackagesFromCommands(targetOS OS, filesMap extractor.FileMap) ([]Package, error) {
	for _, analyzer := range commandAnalyzers {
		pkgs, err := analyzer.Analyze(targetOS, filesMap)
		if err != nil {
			continue
		}
		return pkgs, nil
	}
	return nil, nil
}

func CheckPackage(pkg *Package) bool {
	return pkg.Name != "" && pkg.Version != ""
}

type Application struct {
	Type      string
	FilePath  string
	Libraries []godeptypes.Library
}

func GetLibraries(filesMap extractor.FileMap) ([]Application, error) {
	var results []Application
	for _, analyzer := range libAnalyzers {
		libMap, err := analyzer.Analyze(filesMap)
		if err != nil {
			return nil, xerrors.Errorf("failed to analyze libraries: %w", err)
		}

		for filePath, libs := range libMap {
			results = append(results, Application{
				Type:      analyzer.Name(),
				FilePath:  string(filePath),
				Libraries: libs,
			})
		}
	}
	return results, nil
}

func mergePkgs(pkgs, pkgsFromCommands []Package) []Package {
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
