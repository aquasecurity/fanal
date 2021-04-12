package scanner

import (
	"context"
	_ "embed"
	"regexp"

	"github.com/open-policy-agent/opa/rego"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/policy"
	"github.com/aquasecurity/fanal/types"
)

var (
	//go:embed detection.rego
	defaultDetectionModule string
)

type Scanner struct {
	namespaces  []string
	filePattern *regexp.Regexp
	engine      *policy.Engine
}

func New(filePattern *regexp.Regexp, namespaces, policyPaths, dataPaths []string) (Scanner, error) {
	engine, err := policy.Load(policyPaths, dataPaths)
	if err != nil {
		return Scanner{}, err
	}

	return Scanner{
		namespaces:  namespaces,
		filePattern: filePattern,
		engine:      engine,
	}, nil
}

func (s Scanner) Match(filePath string) bool {
	if s.filePattern == nil {
		return false
	}
	return s.filePattern.MatchString(filePath)
}

func (s Scanner) DetectType(ctx context.Context, input interface{}) (string, error) {
	// The input might include sub documents. In that case, it takes the first element.
	contents, ok := input.([]interface{})
	if ok {
		input = contents[0]
	}

	results, err := rego.New(
		rego.Input(input),
		rego.Query("x = data.config.type.detect"),
		rego.Module("detection.rego", defaultDetectionModule),
	).Eval(ctx)

	if err != nil {
		return "", xerrors.Errorf("rego eval error: %w", err)
	}

	for _, result := range results {
		for _, configType := range result.Bindings["x"].([]interface{}) {
			v, ok := configType.(string)
			if !ok {
				return "", xerrors.Errorf("'detect' must return string")
			}
			// Return the first element
			return v, nil
		}
	}
	return "", nil
}

func (s Scanner) ScanConfigs(ctx context.Context, configs []types.Config) (types.Misconfiguration, error) {
	var configs []types.Config
	for _, config := range configs {
		// Detect config types
		configType, err := s.DetectType(ctx, config)
		if err != nil {
			return types.Misconfiguration{}, err
		}
		if configType != "" {
			config.Type = configType
		}

		// It is possible for a configuration to have multiple configurations. An example of this
		// are multi-document yaml files where a single filepath represents multiple configs.
		//
		// If the current configuration contains multiple configurations, evaluate each policy
		// independent from one another and aggregate the results under the same file name.
		if subconfigs, ok := config.Content.([]interface{}); ok {
			for _, subconfig := range subconfigs {
				configs = append(configs, types.Config{
					Type:     config.Type,
					FilePath: config.FilePath,
					Content:  subconfig,
				})
			}
		} else {
			configs = append(configs, config)
		}

	}
	misconf, err := s.engine.Check(ctx, configType, fileName, content, s.namespaces)
	if err != nil {
		return types.Misconfiguration{}, xerrors.Errorf("failed to scan %s: %w", fileName, err)
	}

	return misconf, nil
}
