package docker

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/conftest/parser/docker"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&dockerConfigAnalyzer{
		parser: &docker.Parser{},
	})
}

const version = 1

var requiredExts = []string{"Dockerfile"}

type dockerConfigAnalyzer struct {
	parser *docker.Parser
}

func (a dockerConfigAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	var parsed interface{}
	if err := a.parser.Unmarshal(target.Content, &parsed); err != nil {
		return nil, xerrors.Errorf("unable to parse Docker (%s): %w", target.FilePath, err)
	}
	return &analyzer.AnalysisResult{
		Configs: []types.Config{{
			Type:     config.Dockerfile,
			FilePath: target.FilePath,
			Content:  parsed,
		}},
	}, nil
}

// Required returns true if base filepath contains of the requiredExts
// case-insensitive
func (a dockerConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	base := filepath.Base(filePath)
	for _, required := range requiredExts {
		if strings.EqualFold(base, required) {
			return true
		}
		if strings.Contains(strings.ToLower(base), strings.ToLower(required)) {
			return true
		}
	}
	return false
}

func (a dockerConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeDockerfile
}

func (a dockerConfigAnalyzer) Version() int {
	return version
}
