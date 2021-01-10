package buildinfo

import (
	"encoding/json"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
)

func init() {
	analyzer.RegisterAnalyzer(&contentManifestAnalyzer{})
}

const (
	name = "redhat content manifest"
)

type contentManifest struct {
	ContentSets []string `json:"content_sets"`
}

// For Red Hat products
type contentManifestAnalyzer struct{}

func (a contentManifestAnalyzer) Analyze(content []byte) (analyzer.AnalyzeReturn, error) {
	var manifest contentManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		return analyzer.AnalyzeReturn{}, xerrors.Errorf("invalid content manifests: %w", err)
	}

	return analyzer.AnalyzeReturn{
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

func (a contentManifestAnalyzer) Name() string {
	return name
}
