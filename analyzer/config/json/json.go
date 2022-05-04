package json

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"

	"github.com/aquasecurity/fanal/config/scanner"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

const version = 1

var (
	requiredExt   = ".json"
	excludedFiles = []string{types.NpmPkgLock, types.NuGetPkgsLock, types.NuGetPkgsConfig}
)

type ConfigAnalyzer struct {
	filePattern *regexp.Regexp
}

func NewConfigAnalyzer(filePattern *regexp.Regexp) ConfigAnalyzer {
	return ConfigAnalyzer{
		filePattern: filePattern,
	}
}

func (a ConfigAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	var parsed interface{}
	var confType string
	err := json.NewDecoder(input.Content).Decode(&parsed)
	if err != nil {
		return nil, xerrors.Errorf("unable to decode JSON (%s): %w", input.FilePath, err)
	}

	if configs, ok := parsed.([]interface{}); ok { // json input is array
		for _, c := range configs {
			confType, err = scanner.DetectType(ctx, c)
			if err != nil {
				return nil, xerrors.Errorf("unable to detect config type from JSON (%s): %w", input.FilePath, err)
			}
			if confType != "" {
				break
			}
		}
	} else {
		confType, err = scanner.DetectType(ctx, parsed)
		if err != nil {
			return nil, xerrors.Errorf("unable to detect config type from JSON (%s): %w", input.FilePath, err)
		}
	}

	if confType != "" { // skip file if can't determine config type
		return &analyzer.AnalysisResult{
			Configs: []types.Config{
				{
					Type:     confType,
					FilePath: input.FilePath,
					Content:  parsed,
				},
			},
		}, nil
	}
	return &analyzer.AnalysisResult{}, err
}

func (a ConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	if a.filePattern != nil && a.filePattern.MatchString(filePath) {
		return true
	}

	filename := filepath.Base(filePath)
	for _, excludedFile := range excludedFiles {
		if filename == excludedFile {
			return false
		}
	}

	return filepath.Ext(filePath) == requiredExt
}

func (ConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeJSON
}

func (ConfigAnalyzer) Version() int {
	return version
}
