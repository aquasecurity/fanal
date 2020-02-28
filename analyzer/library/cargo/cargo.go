package cargo

import (
	"bytes"
	"path/filepath"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/cargo"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterLibraryAnalyzer(&cargoLibraryAnalyzer{})
}

type cargoLibraryAnalyzer struct{}

func (a cargoLibraryAnalyzer) Analyze(fileMap extractor.FileMap) (map[types.FilePath][]types.LibraryInfo, error) {
	libMap := map[types.FilePath][]types.LibraryInfo{}
	requiredFiles := a.RequiredFiles()

	for filename, content := range fileMap {
		basename := filepath.Base(filename)
		if !utils.StringInSlice(basename, requiredFiles) {
			continue
		}

		r := bytes.NewBuffer(content)
		libs, err := cargo.Parse(r)
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

func (a cargoLibraryAnalyzer) RequiredFiles() []string {
	return []string{"Cargo.lock"}
}

func (a cargoLibraryAnalyzer) Name() string {
	return library.Cargo
}
