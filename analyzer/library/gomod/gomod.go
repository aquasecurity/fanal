package gomod

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/gomod"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
)

func init() {
	analyzer.RegisterAnalyzer(&gomodAnalyzer{})
}

const version = 1

type gomodAnalyzer struct{}

var requiredExtensions = []string{".sum"}

func (a gomodAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	res, err := library.Analyze(library.GoMod, target.FilePath, target.Content, gomod.Parse)
	if err != nil {
		return nil, xerrors.Errorf("error with go.sum: %w", err)
	}
	return res, nil
}

func (a gomodAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	for _, required := range requiredExtensions {
		if strings.EqualFold(ext, required) {
			return true
		}
	}
	return false
}

func (a gomodAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGoMod
}

func (a gomodAnalyzer) Version() int {
	return version
}
