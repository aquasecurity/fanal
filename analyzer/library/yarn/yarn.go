package yarn

import (
	"bytes"
	"path/filepath"
	"strings"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/extractor"
	"github.com/knqyf263/fanal/utils"
	"github.com/knqyf263/go-dep-parser/pkg/types"
	"github.com/knqyf263/go-dep-parser/pkg/yarn"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterLibraryAnalyzer(&yarnLibraryAnalyzer{})
}

type yarnLibraryAnalyzer struct{}

func (a yarnLibraryAnalyzer) Analyze(fileMap extractor.FileMap) (map[analyzer.FilePath][]types.Library, error) {
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
		libs, err := yarn.Parse(r)
		if err != nil {
			return nil, xerrors.Errorf("invalid yarn.lock format: %w", err)
		}
		libMap[analyzer.FilePath(filename)] = libs
	}

	return libMap, nil
}

func (a yarnLibraryAnalyzer) RequiredFiles() []string {
	return []string{"yarn.lock"}
}
