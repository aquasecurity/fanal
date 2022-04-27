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

var requiredExtensions = []string{".jar", ".war", ".ear", ".par"}

// javaLibraryAnalyzer analyzes jar/war/ear/par files
type javaLibraryAnalyzer struct{}

func (a javaLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	p := jar.NewParser(jar.WithSize(input.Info.Size()), jar.WithFilePath(input.FilePath), jar.WithOffline(input.Options.Offline))

	res, err := language.Analyze(types.Jar, input.FilePath, input.Content, p)
	if err != nil {
		return nil, xerrors.Errorf("jar/war/ear/par parse error: %w", err)
	}
	//Library path should be taken from input for this particular parser
	for _, app := range res.Applications {
		for i := range app.Libraries {
			app.Libraries[i].FilePath = input.FilePath
		}
	}

	return res, nil
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
