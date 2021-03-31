package scanner

import (
	"context"
	_ "embed"
	"regexp"

	"github.com/open-policy-agent/opa/rego"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer/config/policy"
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
		return "", err
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

func (s Scanner) ScanConfig(configType, fileName string, content interface{}) (types.Misconfiguration, error) {
	ctx := context.TODO()

	misconf, err := s.engine.Check(ctx, configType, fileName, content, s.namespaces)
	if err != nil {
		return types.Misconfiguration{}, xerrors.Errorf("failed to scan %s: %w", fileName, err)
	}

	return misconf, nil
}
