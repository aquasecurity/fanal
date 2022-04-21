package image

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/analyzer/secret"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/config/scanner"
	"github.com/aquasecurity/fanal/hook"
	"github.com/aquasecurity/fanal/log"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/walker"
)

const (
	parallel = 5
)

type Artifact struct {
	image       types.Image
	cache       cache.ArtifactCache
	walker      walker.LayerTar
	analyzer    analyzer.AnalyzerGroup
	hookManager hook.Manager
	scanner     scanner.Scanner

	artifactOption artifact.Option
}

func NewArtifact(img types.Image, c cache.ArtifactCache, opt artifact.Option) (artifact.Artifact, error) {
	misconf := opt.MisconfScannerOption
	// Register config analyzers
	if err := config.RegisterConfigAnalyzers(misconf.FilePatterns); err != nil {
		return nil, xerrors.Errorf("config scanner error: %w", err)
	}

	s, err := scanner.New("", misconf.Namespaces, misconf.PolicyPaths, misconf.DataPaths, misconf.Trace)
	if err != nil {
		return nil, xerrors.Errorf("scanner init error: %w", err)
	}

	// Register secret analyzer
	if err = secret.RegisterSecretAnalyzer(opt.SecretScannerOption); err != nil {
		return nil, xerrors.Errorf("secret scanner error: %w", err)
	}

	return Artifact{
		image:       img,
		cache:       c,
		walker:      walker.NewLayerTar(opt.SkipFiles, opt.SkipDirs),
		analyzer:    analyzer.NewAnalyzerGroup(opt.AnalyzerGroup, opt.DisabledAnalyzers),
		hookManager: hook.NewManager(opt.DisabledHooks),
		scanner:     s,

		artifactOption: opt,
	}, nil
}

func (a Artifact) Inspect(ctx context.Context) (types.ArtifactReference, error) {
	imageID, err := a.image.ID()
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get the image ID: %w", err)
	}

	diffIDs, err := a.image.LayerIDs()
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get layer IDs: %w", err)
	}

	configFile, err := a.image.ConfigFile()
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get the image's config file: %w", err)
	}

	// Debug
	log.Logger.Debugf("Image ID: %s", imageID)
	log.Logger.Debugf("Diff IDs: %v", diffIDs)

	// Try to detect base layers.
	baseDiffIDs := a.guessBaseLayers(diffIDs, configFile)
	log.Logger.Debugf("Base Layers: %v", baseDiffIDs)

	// Convert image ID and layer IDs to cache keys
	imageKey, layerKeys, layerKeyMap, err := a.calcCacheKeys(imageID, diffIDs)
	if err != nil {
		return types.ArtifactReference{}, err
	}

	missingImage, missingLayers, err := a.cache.MissingBlobs(imageKey, layerKeys)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get missing layers: %w", err)
	}

	missingImageKey := imageKey
	if missingImage {
		log.Logger.Debugf("Missing image ID in cache: %s", imageID)
	} else {
		missingImageKey = ""
	}

	if err = a.inspect(ctx, missingImageKey, missingLayers, baseDiffIDs, layerKeyMap); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("analyze error: %w", err)
	}

	return types.ArtifactReference{
		Name:    a.image.Name(),
		Type:    types.ArtifactContainerImage,
		ID:      imageKey,
		BlobIDs: layerKeys,
		ImageMetadata: types.ImageMetadata{
			ID:          imageID,
			DiffIDs:     diffIDs,
			RepoTags:    a.image.RepoTags(),
			RepoDigests: a.image.RepoDigests(),
			ConfigFile:  *configFile,
		},
	}, nil
}

func (Artifact) Clean(_ types.ArtifactReference) error {
	return nil
}

func (a Artifact) calcCacheKeys(imageID string, diffIDs []string) (string, []string, map[string]string, error) {
	// Pass an empty config scanner option so that the cache key can be the same, even when policies are updated.
	imageKey, err := cache.CalcKey(imageID, a.analyzer.ImageConfigAnalyzerVersions(), nil, artifact.Option{})
	if err != nil {
		return "", nil, nil, err
	}

	layerKeyMap := map[string]string{}
	hookVersions := a.hookManager.Versions()
	var layerKeys []string
	for _, diffID := range diffIDs {
		blobKey, err := cache.CalcKey(diffID, a.analyzer.AnalyzerVersions(), hookVersions, a.artifactOption)
		if err != nil {
			return "", nil, nil, err
		}
		layerKeys = append(layerKeys, blobKey)
		layerKeyMap[blobKey] = diffID
	}
	return imageKey, layerKeys, layerKeyMap, nil
}

func (a Artifact) inspect(ctx context.Context, missingImage string, layerKeys, baseDiffIDs []string, layerKeyMap map[string]string) error {
	done := make(chan struct{})
	errCh := make(chan error)

	var osFound types.OS
	for _, k := range layerKeys {
		go func(ctx context.Context, layerKey string) {
			diffID := layerKeyMap[layerKey]

			// If it is a base layer, secret scanning should not be performed.
			var disabledAnalyers []analyzer.Type
			if slices.Contains(baseDiffIDs, diffID) {
				disabledAnalyers = append(disabledAnalyers, analyzer.TypeSecret)
			}

			layerInfo, err := a.inspectLayer(ctx, diffID, disabledAnalyers)
			if err != nil {
				errCh <- xerrors.Errorf("failed to analyze layer: %s : %w", diffID, err)
				return
			}
			if err = a.cache.PutBlob(layerKey, layerInfo); err != nil {
				errCh <- xerrors.Errorf("failed to store layer: %s in cache: %w", layerKey, err)
				return
			}
			if layerInfo.OS != nil {
				osFound = *layerInfo.OS
			}
			done <- struct{}{}
		}(ctx, k)
	}

	for range layerKeys {
		select {
		case <-done:
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return xerrors.Errorf("timeout: %w", ctx.Err())
		}
	}

	if missingImage != "" {
		if err := a.inspectConfig(missingImage, osFound); err != nil {
			return xerrors.Errorf("unable to analyze config: %w", err)
		}
	}

	return nil

}

func (a Artifact) inspectLayer(ctx context.Context, diffID string, disabled []analyzer.Type) (types.BlobInfo, error) {
	log.Logger.Debugf("Missing diff ID in cache: %s", diffID)

	layerDigest, r, err := a.uncompressedLayer(diffID)
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("unable to get uncompressed layer %s: %w", diffID, err)
	}

	var wg sync.WaitGroup
	result := new(analyzer.AnalysisResult)
	limit := semaphore.NewWeighted(parallel)

	opqDirs, whFiles, err := a.walker.Walk(r, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		opts := analyzer.AnalysisOptions{Offline: a.artifactOption.Offline}
		if err = a.analyzer.AnalyzeFile(ctx, &wg, limit, result, "", filePath, info, opener, disabled, opts); err != nil {
			return xerrors.Errorf("failed to analyze %s: %w", filePath, err)
		}
		return nil
	})
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("walk error: %w", err)
	}

	// Wait for all the goroutine to finish.
	wg.Wait()

	// Sort the analysis result for consistent results
	result.Sort()

	blobInfo := types.BlobInfo{
		SchemaVersion:   types.BlobJSONSchemaVersion,
		Digest:          layerDigest,
		DiffID:          diffID,
		OS:              result.OS,
		Repository:      result.Repository,
		PackageInfos:    result.PackageInfos,
		Applications:    result.Applications,
		Secrets:         result.Secrets,
		SystemFiles:     result.SystemInstalledFiles,
		OpaqueDirs:      opqDirs,
		WhiteoutFiles:   whFiles,
		CustomResources: result.CustomResources,

		// For Red Hat
		BuildInfo: result.BuildInfo,
	}

	// Call hooks to modify blob info
	if err = a.hookManager.CallHooks(&blobInfo); err != nil {
		return types.BlobInfo{}, xerrors.Errorf("failed to call hooks: %w", err)
	}

	return blobInfo, nil
}

func (a Artifact) uncompressedLayer(diffID string) (string, io.Reader, error) {
	// diffID is a hash of the uncompressed layer
	h, err := v1.NewHash(diffID)
	if err != nil {
		return "", nil, xerrors.Errorf("invalid layer ID (%s): %w", diffID, err)
	}

	layer, err := a.image.LayerByDiffID(h)
	if err != nil {
		return "", nil, xerrors.Errorf("failed to get the layer (%s): %w", diffID, err)
	}

	// digest is a hash of the compressed layer
	var digest string
	if a.isCompressed(layer) {
		d, err := layer.Digest()
		if err != nil {
			return "", nil, xerrors.Errorf("failed to get the digest (%s): %w", diffID, err)
		}
		digest = d.String()
	}

	r, err := layer.Uncompressed()
	if err != nil {
		return "", nil, xerrors.Errorf("failed to get the layer content (%s): %w", diffID, err)
	}
	return digest, r, nil
}

// ref. https://github.com/google/go-containerregistry/issues/701
func (a Artifact) isCompressed(l v1.Layer) bool {
	_, uncompressed := reflect.TypeOf(l).Elem().FieldByName("UncompressedLayer")
	return !uncompressed
}

func (a Artifact) inspectConfig(imageID string, osFound types.OS) error {
	configBlob, err := a.image.RawConfigFile()
	if err != nil {
		return xerrors.Errorf("unable to get config blob: %w", err)
	}

	pkgs := a.analyzer.AnalyzeImageConfig(osFound, configBlob)

	var s1 v1.ConfigFile
	if err = json.Unmarshal(configBlob, &s1); err != nil {
		return xerrors.Errorf("json marshal error: %w", err)
	}

	info := types.ArtifactInfo{
		SchemaVersion:   types.ArtifactJSONSchemaVersion,
		Architecture:    s1.Architecture,
		Created:         s1.Created.Time,
		DockerVersion:   s1.DockerVersion,
		OS:              s1.OS,
		HistoryPackages: pkgs,
	}

	if err = a.cache.PutArtifact(imageID, info); err != nil {
		return xerrors.Errorf("failed to put image info into the cache: %w", err)
	}

	return nil
}

// Guess layers in base image (call base layers).
//
// e.g. In the following example, we should detect layers in debian:8.
//   FROM debian:8
//   RUN apt-get update
//   COPY mysecret /
//   ENTRYPOINT ["entrypoint.sh"]
//   CMD ["somecmd"]
//
// debian:8 may be like
//   ADD file:5d673d25da3a14ce1f6cf66e4c7fd4f4b85a3759a9d93efb3fd9ff852b5b56e4 in /
//   CMD ["/bin/sh"]
//
// In total, it would be like:
//   ADD file:5d673d25da3a14ce1f6cf66e4c7fd4f4b85a3759a9d93efb3fd9ff852b5b56e4 in /
//   CMD ["/bin/sh"]              # empty layer (detected)
//   RUN apt-get update
//   COPY mysecret /
//   ENTRYPOINT ["entrypoint.sh"] # empty layer (skipped)
//   CMD ["somecmd"]              # empty layer (skipped)
//
// This method tries to detect CMD in the second line and assume the first line is a base layer.
//   1. Iterate histories from the bottom.
//   2. Skip all the empty layers at the bottom. In the above example, "entrypoint.sh" and "somecmd" will be skipped
//   3. If it finds CMD, it assumes that it is the end of base layers.
//   4. It gets all the layers as base layers above the CMD found in #3.
func (a Artifact) guessBaseLayers(diffIDs []string, configFile *v1.ConfigFile) []string {
	if configFile == nil {
		return nil
	}

	var baseImageIndex int
	var foundNonEmpty bool
	for i := len(configFile.History) - 1; i >= 0; i-- {
		h := configFile.History[i]

		// Skip the last CMD, ENTRYPOINT, etc.
		if !foundNonEmpty {
			if h.EmptyLayer {
				continue
			}
			foundNonEmpty = true
		}

		if !h.EmptyLayer {
			continue
		}

		// Detect CMD instruction in base image
		if strings.HasPrefix(h.CreatedBy, "/bin/sh -c #(nop)  CMD") ||
			strings.HasPrefix(h.CreatedBy, "CMD") { // BuildKit
			baseImageIndex = i
			break
		}
	}

	// Diff IDs don't include empty layers, so the index is different from histories
	var diffIDIndex int
	var baseDiffIDs []string
	for i, h := range configFile.History {
		// It is no longer base layer.
		if i > baseImageIndex {
			break
		}
		// Empty layers are not included in diff IDs.
		if h.EmptyLayer {
			continue
		}

		if diffIDIndex >= len(diffIDs) {
			// something wrong...
			return nil
		}
		baseDiffIDs = append(baseDiffIDs, diffIDs[diffIDIndex])
		diffIDIndex++
	}
	return baseDiffIDs
}
