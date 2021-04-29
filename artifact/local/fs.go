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
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/walker"
)

const (
	parallel = 10
)

type Artifact struct {
	dir      string
	cache    cache.ArtifactCache
	analyzer analyzer.Analyzer
}

func NewArtifact(dir string, c cache.ArtifactCache, disabled []analyzer.Type) artifact.Artifact {
	return Artifact{
		dir:      dir,
		cache:    c,
		analyzer: analyzer.NewAnalyzer(disabled),
	}
}

func (a Artifact) Inspect(ctx context.Context) (types.ArtifactReference, error) {
	var wg sync.WaitGroup
	result := new(analyzer.AnalysisResult)
	limit := semaphore.NewWeighted(parallel)

	err := walker.WalkDir(a.dir, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		filePath, err := filepath.Rel(a.dir, filePath)
		if err != nil {
			return xerrors.Errorf("filepath rel (%s): %w", filePath, err)
		}
		if err = a.analyzer.AnalyzeFile(ctx, &wg, limit, result, filePath, info, opener); err != nil {
			return xerrors.Errorf("analyze file (%s): %w", filePath, err)
		}
		return nil
	})
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("walk dir: %w", err)
	}

	// Wait for all the goroutine to finish.
	wg.Wait()

	result.Sort()

	blobInfo := types.BlobInfo{
		SchemaVersion: types.BlobJSONSchemaVersion,
		OS:            result.OS,
		PackageInfos:  result.PackageInfos,
		Applications:  result.Applications,
		Configs:       result.Configs,
	}

	// calculate hash of JSON and use it as pseudo artifactID and blobID
	h := sha256.New()
	if err = json.NewEncoder(h).Encode(blobInfo); err != nil {
		return types.ArtifactReference{}, err
	}

	d := digest.NewDigest(digest.SHA256, h)
	diffID := d.String()
	blobInfo.DiffID = diffID
	versionedDiffID := cache.WithVersionSuffix(diffID, a.analyzer.AnalyzerVersions())

	if err = a.cache.PutBlob(versionedDiffID, blobInfo); err != nil {
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
		ID:      versionedDiffID, // use diffID as pseudo artifactID
		BlobIDs: []string{versionedDiffID},
	}, nil
}
