package npm

import (
	"bytes"
	"path/filepath"
	"strings"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/extractor"
	"github.com/knqyf263/fanal/utils"
	"github.com/knqyf263/go-dep-parser/pkg/npm"
	"github.com/knqyf263/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterLibraryAnalyzer(&npmLibraryAnalyzer{})
}

type npmLibraryAnalyzer struct{}

func (a npmLibraryAnalyzer) Analyze(fileMap extractor.FileMap) (map[analyzer.FilePath][]types.Library, error) {
	libMap := map[analyzer.FilePath][]types.Library{}
	requiredFiles := a.RequiredFiles()

	for filename, content := range fileMap {
		basename := filepath.Base(filename)
		if !utils.StringInSlice(basename, requiredFiles) {
			continue
		}

		// skip analyze files which in dependency folder
		if utils.StringInSlice(utils.NODE_DEP_DIR, strings.Split(filename, utils.PathSeparator)) {
			continue
		}

		r := bytes.NewBuffer(content.Body)
		libs, err := npm.Parse(r)
		if err != nil {
			return nil, xerrors.Errorf("invalid package-lock.json format: %w", err)
		}
		libMap[analyzer.FilePath(filename)] = libs
	}
	return libMap, nil
}

func (a npmLibraryAnalyzer) RequiredFiles() []string {
	return []string{"package-lock.json"}
}
