package yarn

import (
	"bytes"
	"path/filepath"

	"github.com/aquasecurity/fanal/types"

	"github.com/aquasecurity/fanal/analyzer/library"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/yarn"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterLibraryAnalyzer(&yarnLibraryAnalyzer{})
}

type yarnLibraryAnalyzer struct{}

func (a yarnLibraryAnalyzer) Analyze(fileMap extractor.FileMap) (map[types.FilePath][]types.LibraryInfo, error) {
	libMap := map[types.FilePath][]types.LibraryInfo{}
	requiredFiles := a.RequiredFiles()

	for filename, content := range fileMap {

		basename := filepath.Base(filename)

		if !utils.StringInSlice(basename, requiredFiles) {
			continue
		}

		r := bytes.NewBuffer(content)
		libs, err := yarn.Parse(r)
		if err != nil {
			return nil, xerrors.Errorf("error with %s: %w", filename, err)
		}
		for _, lib := range libs {
			libMap[types.FilePath(filename)] = append(libMap[types.FilePath(filename)], types.LibraryInfo{
				Library: lib,
			})
		}
	}

	return libMap, nil
}

func (a yarnLibraryAnalyzer) RequiredFiles() []string {
	return []string{"yarn.lock"}
}

func (a yarnLibraryAnalyzer) Name() string {
	return library.Yarn
}
