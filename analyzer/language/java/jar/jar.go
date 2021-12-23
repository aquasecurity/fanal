package jar

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/language"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/go-dep-parser/pkg/java/jar"
)

func init() {
	analyzer.RegisterAnalyzer(&javaLibraryAnalyzer{})
}

const version = 1

var requiredExtensions = []string{".jar", ".war", ".ear"}

// javaLibraryAnalyzer analyzes jar/war/ear files
type javaLibraryAnalyzer struct{}

func (a javaLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	libs, err := jar.Parse(input.Content, input.Info.Size(), jar.WithFilePath(input.FilePath))
	if err != nil {
		return nil, xerrors.Errorf("jar/war/ear parse error: %w", err)
	}

	return language.ToAnalysisResult(types.Jar, input.FilePath, input.FilePath, libs), nil
}

func (a javaLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	for _, required := range requiredExtensions {
		if strings.EqualFold(ext, required) {
			return true
		}
	}
	return false
}

func (a javaLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeJar
}

func (a javaLibraryAnalyzer) Version() int {
	return version
}
