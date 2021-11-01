package buildinfo

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
)

func init() {
	analyzer.RegisterAnalyzer(&contentManifestAnalyzer{})
}

const contentManifestAnalyzerversion = 1

type contentManifest struct {
	ContentSets []string `json:"content_sets"`
}

// For Red Hat products
type contentManifestAnalyzer struct{}

func (a contentManifestAnalyzer) Analyze(ctx context.Context, target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	var manifest contentManifest
	if err := json.Unmarshal(target.Content, &manifest); err != nil {
		return nil, xerrors.Errorf("invalid content manifests: %w", err)
	}

	return &analyzer.AnalysisResult{
		BuildInfo: &analyzer.BuildInfo{
			ContentSets: manifest.ContentSets,
		},
	}, nil
}

func (a contentManifestAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	dir, file := filepath.Split(filePath)
	if dir != "root/buildinfo/content_manifests/" {
		return false
	}
	return filepath.Ext(file) == ".json"
}

func (a contentManifestAnalyzer) Type() analyzer.Type {
	return "redhat content manifest"
}

func (a contentManifestAnalyzer) Version() int {
	return contentManifestAnalyzerversion
}
