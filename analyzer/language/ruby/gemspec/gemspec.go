package gemspec

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/aquasecurity/go-dep-parser/pkg/ruby/gemspec"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&gemspecLibraryAnalyzer{})
}

const version = 1

var fileRegex = regexp.MustCompile(`.*/specifications/.+\.gemspec`)

type gemspecLibraryAnalyzer struct{}

func (a gemspecLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	parsedLib, err := gemspec.Parse(input.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", input.FilePath, err)
	}

	return &analyzer.AnalysisResult{
		Applications: []types.Application{
			{
				Type:     types.GemSpec,
				FilePath: input.FilePath,
				Libraries: []types.Package{
					{
						Name:     parsedLib.Name,
						Version:  parsedLib.Version,
						License:  parsedLib.License,
						FilePath: input.FilePath,
					},
				},
			},
		},
	}, nil
}

func (a gemspecLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return fileRegex.MatchString(filepath.ToSlash(filePath))
}

func (a gemspecLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGemSpec
}

func (a gemspecLibraryAnalyzer) Version() int {
	return version
}
