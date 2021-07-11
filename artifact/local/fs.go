package local

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	digest "github.com/opencontainers/go-digest"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/config/scanner"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/walker"
)

const (
	parallel = 10
)

type Artifact struct {
	dir                 string
	cache               cache.ArtifactCache
	analyzer            analyzer.Analyzer
	scanner             scanner.Scanner
	configScannerOption config.ScannerOption
}

func NewArtifact(dir string, c cache.ArtifactCache, disabled []analyzer.Type, opt config.ScannerOption) (artifact.Artifact, error) {
	// Register config analyzers
	if err := config.RegisterConfigAnalyzers(opt.FilePatterns); err != nil {
		return nil, xerrors.Errorf("config analyzer error: %w", err)
	}

	s, err := scanner.New(dir, opt.Namespaces, opt.PolicyPaths, opt.DataPaths, opt.Trace)
	if err != nil {
		return nil, xerrors.Errorf("scanner error: %w", err)
	}

	return Artifact{
		dir:                 dir,
		cache:               c,
		analyzer:            analyzer.NewAnalyzer(disabled),
		scanner:             s,
		configScannerOption: opt,
	}, nil
}

func (a Artifact) Inspect(ctx context.Context) (types.ArtifactReference, error) {
	var wg sync.WaitGroup
	result := new(analyzer.AnalysisResult)
	limit := semaphore.NewWeighted(parallel)

	err := walker.WalkDir(a.dir, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		// For exported rootfs (e.g. images/alpine/etc/alpine-release)
		filePath, err := filepath.Rel(a.dir, filePath)
		if err != nil {
			return xerrors.Errorf("filepath rel (%s): %w", filePath, err)
		}
		if err = a.analyzer.AnalyzeFile(ctx, &wg, limit, result, a.dir, filePath, info, opener); err != nil {
			return xerrors.Errorf("analyze file (%s): %w", filePath, err)
		}
		return nil
	})
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("walk dir: %w", err)
	}

	// Wait for all the goroutine to finish.
	wg.Wait()

	// Sort the analysis result for consistent results
	result.Sort()

	// Scan config files
	misconfs, err := a.scanner.ScanConfigs(ctx, result.Configs)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("config scan error: %w", err)
	}

	blobInfo := types.BlobInfo{
		SchemaVersion:     types.BlobJSONSchemaVersion,
		OS:                result.OS,
		PackageInfos:      result.PackageInfos,
		Applications:      result.Applications,
		Misconfigurations: misconfs,
	}

	// calculate hash of JSON and use it as pseudo artifactID and blobID
	h := sha256.New()
	if err = json.NewEncoder(h).Encode(blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("json error: %w", err)
	}

	d := digest.NewDigest(digest.SHA256, h)
	diffID := d.String()
	blobInfo.DiffID = diffID
	cacheKey, err := cache.CalcKey(diffID, a.analyzer.AnalyzerVersions(), &a.configScannerOption)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("cache key: %w", err)
	}

	if err = a.cache.PutBlob(cacheKey, blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to store blob (%s) in cache: %w", diffID, err)
	}

	// get hostname
	var hostName string
	b, err := ioutil.ReadFile(filepath.Join(a.dir, "etc", "hostname"))
	if err == nil && string(b) != "" {
		hostName = strings.TrimSpace(string(b))
	} else {
		hostName = a.dir
	}

	return types.ArtifactReference{
		Name:    hostName,
		Type:    types.ArtifactFilesystem,
		ID:      cacheKey, // use a cache key as pseudo artifact ID
		BlobIDs: []string{cacheKey},
	}, nil
}
