package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"golang.org/x/xerrors"
	"io"
	"os"
	"path/filepath"
)

func init() {
	analyzer.RegisterAnalyzer(&pkgManifestAnalyzer{})
}

var requiredFiles = []string{"manifest.trivy"}

type pkgManifestAnalyzer struct{}

type PkgManifestEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (a pkgManifestAnalyzer) Analyze(content []byte) (analyzer.AnalyzeReturn, error) {
	result, err := parse(bytes.NewBuffer(content))

	if err != nil {
		return analyzer.AnalyzeReturn{}, xerrors.Errorf("unable to parse manifest.trivy: %w", err)
	}
	return analyzer.AnalyzeReturn{
		Packages: result,
	}, nil
}

func parse(r io.Reader) ([]types.Package, error) {
	decoder := json.NewDecoder(r)
	// The manifest.trivy file is a json file with objects which
	// used the `types.Package` structure. This to make it possible to use either or
	// all the properties that is supported.
	// The most important ones are though, of course, version and name.
	var result []types.Package
	err := decoder.Decode(&result)

	if err != nil {
		return nil, err
	}

	var pkgs []types.Package
	unique := map[string]struct{}{}

	for _, pkg := range result {
		symbol := fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)

		if _, ok := unique[symbol]; ok {
			continue
		}

		pkgs = append(pkgs, pkg)
		unique[symbol] = struct{}{}
	}

	return pkgs, nil
}

func (a pkgManifestAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a pkgManifestAnalyzer) Name() string {
	return library.Manifest
}
