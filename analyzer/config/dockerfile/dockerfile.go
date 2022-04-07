package dockerfile

import (
	"context"
	"github.com/aquasecurity/fanal/config/scanner"
	"github.com/aquasecurity/fanal/log"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/config/parser/dockerfile"
	"github.com/aquasecurity/fanal/types"
)

const version = 1

var requiredFile = "Dockerfile"

type PostAnalyzer struct {
	parser      *dockerfile.Parser
	filePattern *regexp.Regexp
	scanner     *scanner.Scanner
}

func NewPostAnalyzer(scanner *scanner.Scanner, filePattern *regexp.Regexp) PostAnalyzer {
	return PostAnalyzer{
		parser:      &dockerfile.Parser{},
		filePattern: filePattern,
		scanner:     scanner,
	}
}

func (a PostAnalyzer) Analyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var configs []types.Config
	err := fs.WalkDir(input.Fs, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		} else if d.IsDir() {
			return nil
		}

		f, err := input.Fs.Open(path)
		if err != nil {
			return xerrors.Errorf("file open error: %w", err)
		}
		defer f.Close()

		parsed, err := a.parser.Parse(f)
		if err != nil {
			// Skip broken dockerfile
			log.Logger.Debugf("Dockerfile parse error %s: %s", path, err)
			return nil
		}

		configs = append(configs, types.Config{
			Type:     types.Dockerfile,
			FilePath: path,
			Content:  parsed,
		})
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("dockerfile walk error: %w", err)
	}

	misconfs, err := a.scanner.ScanConfigs(ctx, configs)
	if err != nil {
		return nil, xerrors.Errorf("scan config error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Misconfigurations: misconfs,
	}, nil
}

// Required does a case-insensitive check for filePath and returns true if
// filePath equals/startsWith/hasExtension requiredFile
func (a PostAnalyzer) Required(filePath string, _ os.FileInfo, _ analyzer.Opener) bool {
	if a.filePattern != nil && a.filePattern.MatchString(filePath) {
		return true
	}

	base := filepath.Base(filePath)
	ext := filepath.Ext(base)
	if strings.EqualFold(base, requiredFile+ext) {
		return true
	}
	if strings.EqualFold(ext, "."+requiredFile) {
		return true
	}

	return false
}

func (a PostAnalyzer) Type() analyzer.Type {
	return analyzer.TypeDockerfile
}

func (a PostAnalyzer) Version() int {
	return version
}
