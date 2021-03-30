package hcl

import (
	"os"
	"path/filepath"
	"regexp"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/open-policy-agent/conftest/parser/hcl1"
	"github.com/open-policy-agent/conftest/parser/hcl2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config/scanner"
	"github.com/aquasecurity/fanal/types"
)

const version = 1

var requiredExts = []string{".hcl", ".hcl1", ".hcl2", ".tf"}

type ConfigScanner struct {
	hcl1Parser *hcl1.Parser
	hcl2Parser *hcl2.Parser
	scanner.Scanner
}

func NewConfigScanner(filePattern *regexp.Regexp, namespaces, policyPaths, dataPaths []string) (ConfigScanner, error) {
	s, err := scanner.New(filePattern, namespaces, policyPaths, dataPaths)
	if err != nil {
		return ConfigScanner{}, xerrors.Errorf("unable to initialize config scanner: %w", err)
	}

	return ConfigScanner{
		hcl1Parser: &hcl1.Parser{},
		hcl2Parser: &hcl2.Parser{},
		Scanner:    s,
	}, nil
}

// Analyze analyzes HCL-based config files, defaulting to HCL2.0 spec
// it returns error only if content does not comply to both HCL2.0 and HCL1.0 spec
func (s ConfigScanner) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	parsed, err := s.analyze(target)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse HCL (%s): %w", target.FilePath, err)
	}

	result, err := s.ScanConfig(types.HCL, target.FilePath, parsed)
	if err != nil {
		return nil, xerrors.Errorf("unable to scan HCL (%s): %w", target.FilePath, err)
	}

	return &analyzer.AnalysisResult{
		Misconfigurations: []types.Misconfiguration{result},
	}, nil
}

func (s ConfigScanner) analyze(target analyzer.AnalysisTarget) (interface{}, error) {
	var errs error
	var parsed interface{}

	if err := s.hcl2Parser.Unmarshal(target.Content, &parsed); err != nil {
		errs = multierror.Append(errs, xerrors.Errorf("unable to parse HCL2 (%s): %w", target.FilePath, err))
	} else {
		return parsed, nil
	}

	if err := s.hcl1Parser.Unmarshal(target.Content, &parsed); err != nil {
		errs = multierror.Append(errs, xerrors.Errorf("unable to parse HCL1 (%s): %w", target.FilePath, err))
	} else {
		return parsed, nil
	}

	return nil, errs
}

func (s ConfigScanner) Required(filePath string, _ os.FileInfo) bool {
	if s.Match(filePath) {
		return true
	}

	ext := filepath.Ext(filePath)
	for _, required := range requiredExts {
		if ext == required {
			return true
		}
	}
	return false
}

func (s ConfigScanner) Type() analyzer.Type {
	return analyzer.TypeHCL
}

func (s ConfigScanner) Version() int {
	return version
}
