package config

import (
	"regexp"
	"sort"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config/docker"
	"github.com/aquasecurity/fanal/analyzer/config/hcl"
	"github.com/aquasecurity/fanal/analyzer/config/json"
	"github.com/aquasecurity/fanal/analyzer/config/toml"
	"github.com/aquasecurity/fanal/analyzer/config/yaml"
	"github.com/aquasecurity/fanal/log"
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

func RegisterConfigScanners(opt ScannerOption) {
	var dockerRegexp, hclRegexp, jsonRegexp, tomlRegexp, yamlRegexp *regexp.Regexp
	for _, p := range opt.FilePatterns {
		// e.g. "docker:docker_file*"
		s := strings.SplitN(p, separator, 2)
		if len(s) != 2 {
			log.Logger.Warnf("invalid file pattern (%s)", p)
			continue
		}
		fileType, pattern := s[0], s[1]
		r, err := regexp.Compile(pattern)
		if err != nil {
			log.Logger.Warnf("invalid file pattern (%s): %s", pattern, err)
			continue
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
			log.Logger.Warnf("unknown file type: %s, pattern: %s", fileType, pattern)
		}
	}

	analyzer.RegisterAnalyzer(docker.NewConfigScanner(dockerRegexp, opt.Namespaces, opt.PolicyPaths, opt.DataPaths))
	analyzer.RegisterAnalyzer(hcl.NewConfigScanner(hclRegexp, opt.Namespaces, opt.PolicyPaths, opt.DataPaths))
	analyzer.RegisterAnalyzer(json.NewConfigScanner(jsonRegexp, opt.Namespaces, opt.PolicyPaths, opt.DataPaths))
	analyzer.RegisterAnalyzer(toml.NewConfigScanner(tomlRegexp, opt.Namespaces, opt.PolicyPaths, opt.DataPaths))
	analyzer.RegisterAnalyzer(yaml.NewConfigScanner(yamlRegexp, opt.Namespaces, opt.PolicyPaths, opt.DataPaths))
}
