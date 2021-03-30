package config

import (
	"regexp"
	"sort"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config/docker"
	"github.com/aquasecurity/fanal/analyzer/config/hcl"
	"github.com/aquasecurity/fanal/analyzer/config/json"
	"github.com/aquasecurity/fanal/analyzer/config/toml"
	"github.com/aquasecurity/fanal/analyzer/config/yaml"
	"github.com/aquasecurity/fanal/types"
)

const separator = ":"

type ScannerOption struct {
	Namespaces   []string
	FilePatterns []string
	PolicyPaths  []string
	DataPaths    []string
}

func (o *ScannerOption) Sort() {
	sort.Slice(o.FilePatterns, func(i, j int) bool {
		return o.FilePatterns[i] < o.FilePatterns[j]
	})
	sort.Slice(o.PolicyPaths, func(i, j int) bool {
		return o.PolicyPaths[i] < o.PolicyPaths[j]
	})
	sort.Slice(o.DataPaths, func(i, j int) bool {
		return o.DataPaths[i] < o.DataPaths[j]
	})
}

func RegisterConfigScanners(opt ScannerOption) error {
	var dockerRegexp, hclRegexp, jsonRegexp, tomlRegexp, yamlRegexp *regexp.Regexp
	for _, p := range opt.FilePatterns {
		// e.g. "dockerfile:my_dockerfile_*"
		s := strings.SplitN(p, separator, 2)
		if len(s) != 2 {
			return xerrors.Errorf("invalid file pattern (%s)", p)
		}
		fileType, pattern := s[0], s[1]
		r, err := regexp.Compile(pattern)
		if err != nil {
			return xerrors.Errorf("invalid file regexp (%s): %w", p, err)
		}

		switch fileType {
		case types.Dockerfile:
			dockerRegexp = r
		case types.HCL:
			hclRegexp = r
		case types.JSON:
			jsonRegexp = r
		case types.TOML:
			tomlRegexp = r
		case types.YAML:
			yamlRegexp = r
		default:
			return xerrors.Errorf("unknown file type: %s, pattern: %s", fileType, pattern)
		}
	}

	dockerScanner, err := docker.NewConfigScanner(dockerRegexp, opt.Namespaces, opt.PolicyPaths, opt.DataPaths)
	if err != nil {
		return xerrors.Errorf("Dockerfile scanner error: %w", err)
	}

	hclScanner, err := hcl.NewConfigScanner(hclRegexp, opt.Namespaces, opt.PolicyPaths, opt.DataPaths)
	if err != nil {
		return xerrors.Errorf("HCL scanner error: %w", err)
	}

	jsonScanner, err := json.NewConfigScanner(jsonRegexp, opt.Namespaces, opt.PolicyPaths, opt.DataPaths)
	if err != nil {
		return xerrors.Errorf("JSON scanner error: %w", err)
	}

	tomlScanner, err := toml.NewConfigScanner(tomlRegexp, opt.Namespaces, opt.PolicyPaths, opt.DataPaths)
	if err != nil {
		return xerrors.Errorf("TOML scanner error: %w", err)
	}

	yamlScanner, err := yaml.NewConfigScanner(yamlRegexp, opt.Namespaces, opt.PolicyPaths, opt.DataPaths)
	if err != nil {
		return xerrors.Errorf("YAML scanner error: %w", err)
	}

	analyzer.RegisterAnalyzer(dockerScanner)
	analyzer.RegisterAnalyzer(hclScanner)
	analyzer.RegisterAnalyzer(jsonScanner)
	analyzer.RegisterAnalyzer(tomlScanner)
	analyzer.RegisterAnalyzer(yamlScanner)

	return nil
}
