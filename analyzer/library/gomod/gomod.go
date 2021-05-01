package gomod

import (
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/gomod"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&gomodAnalyzer{})
}

const version = 1

type gomodAnalyzer struct{}

var requiredFiles = []string{"go.sum"}

func (a gomodAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	res, err := library.Analyze(library.GoMod, target.FilePath, target.Content, gomod.Parse)
	if err != nil {
		return nil, xerrors.Errorf("error with filePath: %s, err: %w", target.FilePath, err)
	}
	return res, nil
}

func (a gomodAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a gomodAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGoMod
}

func (a gomodAnalyzer) Version() int {
	return version
}
