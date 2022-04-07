package config

import (
	"regexp"
	"sort"
	"strings"

	"github.com/aquasecurity/fanal/analyzer/config/cloudformation"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config/dockerfile"
	"github.com/aquasecurity/fanal/analyzer/config/kubernetes"
	"github.com/aquasecurity/fanal/analyzer/config/terraform"
	"github.com/aquasecurity/fanal/analyzer/config/toml"
	"github.com/aquasecurity/fanal/analyzer/config/yaml"
	"github.com/aquasecurity/fanal/config/scanner"
	"github.com/aquasecurity/fanal/types"
)

const separator = ":"

type ScannerOption struct {
	Trace        bool
	Namespaces   []string
	FilePatterns []string
	PolicyPaths  []string
	DataPaths    []string
}

func (o *ScannerOption) Sort() {
	sort.Strings(o.Namespaces)
	sort.Strings(o.FilePatterns)
	sort.Strings(o.PolicyPaths)
	sort.Strings(o.DataPaths)
}

func RegisterConfigAnalyzers(rootPath string, opt ScannerOption) error {
	var dockerRegexp, k8sRegexp, tomlRegexp, yamlRegexp *regexp.Regexp
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
		case types.Kubernetes:
			k8sRegexp = r
		case types.TOML:
			tomlRegexp = r
		case types.YAML:
			yamlRegexp = r
		default:
			return xerrors.Errorf("unknown file type: %s, pattern: %s", fileType, pattern)
		}
	}

	s, err := scanner.New(rootPath, opt.Namespaces, opt.PolicyPaths, opt.DataPaths, opt.Trace)
	if err != nil {
		return xerrors.Errorf("scanner init error: %w", err)
	}

	analyzer.RegisterPostAnalyzer(dockerfile.NewPostAnalyzer(s, dockerRegexp))
	analyzer.RegisterPostAnalyzer(kubernetes.NewPostAnalyzer(s, k8sRegexp))
	analyzer.RegisterAnalyzer(terraform.NewConfigAnalyzer())
	analyzer.RegisterAnalyzer(cloudformation.NewConfigAnalyzer())
	analyzer.RegisterAnalyzer(toml.NewConfigAnalyzer(tomlRegexp))
	analyzer.RegisterAnalyzer(yaml.NewConfigAnalyzer(yamlRegexp))

	return nil
}
