package scanner

import (
	"context"
	"regexp"
	"strings"

	"github.com/open-policy-agent/conftest/output"
	"github.com/open-policy-agent/conftest/policy"
	"github.com/open-policy-agent/opa/rego"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/log"
	"github.com/aquasecurity/fanal/types"
)

const namespace = "main"
var (
	//go:embed detection.rego
	defaultModule string

	namespaces = []string{"appshield", "user"}
)

type Scanner struct {
	filePattern *regexp.Regexp
	policyPaths []string
	dataPaths   []string
}

func NewScanner(filePattern *regexp.Regexp, policyPaths, dataPaths []string) Scanner {
	return Scanner{
		filePattern: filePattern,
		policyPaths: policyPaths,
		dataPaths:   dataPaths,
	}
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
		rego.Module("detection.rego", defaultModule),
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

	[]types.Misconfiguration, error) {
	ctx := context.TODO()
	configs := map[string]interface{}{
		fileName: content,
	}

	engine, err := policy.LoadWithData(ctx, s.policyPaths, s.dataPaths)
	if err != nil {
		return nil, xerrors.Errorf("policy load error: %w", err)
	}

	result, err := engine.Check(ctx, configs, namespace)
	if err != nil {
		return nil, xerrors.Errorf("query rule: %w", err)
	}

	var results []types.Misconfiguration
	for _, r := range result {
		results = append(results, toMisconfiguration(fileType, r))
	}

	return results, nil
}

func toMisconfiguration(fileType string, r output.CheckResult) types.Misconfiguration {
	var warnings []types.MisconfResult
	for _, w := range r.Warnings {
		warnings = append(warnings, parseResult(w))
	}

	var failures []types.MisconfResult
	for _, f := range r.Failures {
		failures = append(failures, parseResult(f))
	}

	return types.Misconfiguration{
		FileType:  fileType,
		FilePath:  r.FileName,
		Namespace: r.Namespace,
		Successes: r.Successes,
		Warnings:  warnings,
		Failures:  failures,
	}
}

func parseResult(r output.Result) types.MisconfResult {
	policyID := "N/A"
	if v, ok := r.Metadata["id"]; ok {
		switch vv := v.(type) {
		case string:
			policyID = vv
		default:
			log.Logger.Warn("'id' in the policy must be string (%T)", vv)
		}
	}

	checkType := "N/A"
	if v, ok := r.Metadata["type"]; ok {
		switch vv := v.(type) {
		case string:
			checkType = vv
		default:
			log.Logger.Warn("'type' in the policy must be string (%T)", vv)
		}
	}

	severity := "UNKNOWN"
	if v, ok := r.Metadata["severity"]; ok {
		switch vv := v.(type) {
		case string:
			severity = vv
		default:
			log.Logger.Warnf("'severity' in the policy must be string (%T)", vv)
		}
	}

	return types.MisconfResult{
		ID:       policyID,
		Type:     checkType,
		Message:  strings.TrimSpace(r.Message),
		Severity: severity,
	}
}
