package egg

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/go-dep-parser/pkg/egg"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&eggLibraryAnalyzer{})
}

const version = 1

var requiredFile = filepath.Join(".egg-info", "PKG-INFO")

type eggLibraryAnalyzer struct{}

func (a eggLibraryAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	res, err := library.Analyze(types.Egg, target.FilePath, target.Content, egg.Parse)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse METADATA: %w", err)
	}
	return res, nil
}

func (a eggLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return strings.HasSuffix(filePath, requiredFile)
}

func (a eggLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeEgg
}

func (a eggLibraryAnalyzer) Version() int {
	return version
}
