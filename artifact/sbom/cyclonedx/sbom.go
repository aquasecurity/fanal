package cyclonedx

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/CycloneDX/cyclonedx-go"
	digest "github.com/opencontainers/go-digest"
	"golang.org/x/xerrors"
	"os"
	"path/filepath"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/config/scanner"
	"github.com/aquasecurity/fanal/hook"
	"github.com/aquasecurity/fanal/types"
)

type Artifact struct {
	filePath    string
	cache       cache.ArtifactCache
	analyzer    analyzer.AnalyzerGroup
	hookManager hook.Manager
	scanner     scanner.Scanner

	artifactOption      artifact.Option
	configScannerOption config.ScannerOption
}

type TrivyBOM struct {
	cyclonedx.BOM
}

func (b TrivyBOM) BlobInfo() (*types.BlobInfo, error) {
	blobInfo := &types.BlobInfo{}

	return blobInfo, nil
}

func NewArtifact(filePath string, c cache.ArtifactCache, artifactOpt artifact.Option, scannerOpt config.ScannerOption) (artifact.Artifact, error) {
	// Register config analyzers
	if err := config.RegisterConfigAnalyzers(scannerOpt.FilePatterns); err != nil {
		return nil, xerrors.Errorf("config analyzer error: %w", err)
	}

	s, err := scanner.New(filePath, scannerOpt.Namespaces, scannerOpt.PolicyPaths, scannerOpt.DataPaths, scannerOpt.Trace)
	if err != nil {
		return nil, xerrors.Errorf("scanner error: %w", err)
	}

	return Artifact{
		filePath:    filepath.Clean(filePath),
		cache:       c,
		analyzer:    analyzer.NewAnalyzerGroup(artifactOpt.AnalyzerGroup, artifactOpt.DisabledAnalyzers),
		hookManager: hook.NewManager(artifactOpt.DisabledHooks),
		scanner:     s,

		artifactOption:      artifactOpt,
		configScannerOption: scannerOpt,
	}, nil
}

func (a Artifact) Inspect(ctx context.Context) (types.ArtifactReference, error) {
	// result := new(analyzer.AnalysisResult)
	// OS:                result.OS,
	// PackageInfos:      result.PackageInfos,
	// Applications:      result.Applications,
	// SystemFiles:       result.SystemInstalledFiles,
	var err error

	extension := filepath.Ext(a.filePath)

	bom := TrivyBOM{}
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
	if err = a.hookManager.CallHooks(blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to call hooks: %w", err)
	}

	// calculate hash of JSON and use it as pseudo artifactID and blobID
	h := sha256.New()
	if err = json.NewEncoder(h).Encode(blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("json error: %w", err)
	}

	d := digest.NewDigest(digest.SHA256, h)
	diffID := d.String()
	blobInfo.DiffID = diffID
	cacheKey, err := cache.CalcKey(diffID, a.analyzer.AnalyzerVersions(), a.hookManager.Versions(),
		a.artifactOption, a.configScannerOption)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("cache key: %w", err)
	}

	if err = a.cache.PutBlob(cacheKey, *blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to store blob (%s) in cache: %w", diffID, err)
	}

	// get hostname
	var hostName string
	// TODO: get Name for artifact

	return types.ArtifactReference{
		Name:    hostName,
		Type:    types.ArtifactFilesystem,
		ID:      cacheKey, // use a cache key as pseudo artifact ID
		BlobIDs: []string{cacheKey},
	}, nil
}

func (a Artifact) Clean(reference types.ArtifactReference) error {
	return a.cache.DeleteBlobs(reference.BlobIDs)
}
