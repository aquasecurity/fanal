package bundler

import (
	"io"
	"os"
	"path/filepath"

	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/go-dep-parser/pkg/jar"
)

func init() {
	analyzer.RegisterAnalyzer(&javaLibraryAnalyzer{})
}

var (
	requiredExtensions = []string{".jar", ".war", ".ear"}
)

// javaLibraryAnalyzer analyzes jar/war/ear files
type javaLibraryAnalyzer struct{}

func (a javaLibraryAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	parse := func(r io.Reader) ([]godeptypes.Library, error) {
		return jar.Parse(r)
	}
	res, err := library.Analyze(library.Jar, target.FilePath, target.Content, parse)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse jar/war/ear: %w", err)
	}
	return res, nil
}

func (a javaLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	for _, required := range requiredExtensions {
		if ext == required {
			return true
		}
	}
	return false
}

func (a javaLibraryAnalyzer) Name() string {
	return library.Jar
}
