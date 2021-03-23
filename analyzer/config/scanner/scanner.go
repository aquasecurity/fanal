package scanner

import (
	"context"
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"github.com/open-policy-agent/conftest/output"
	"github.com/open-policy-agent/conftest/policy"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/log"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

var (
	//go:embed detection.rego
	defaultModule string
)

type Scanner struct {
	namespaces  []string
	filePattern *regexp.Regexp
	policyPaths []string
	dataPaths   []string
}

func NewScanner(filePattern *regexp.Regexp, namespaces, policyPaths, dataPaths []string) Scanner {
	return Scanner{
		namespaces:  namespaces,
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

func (s Scanner) ScanConfig(configType, fileName string, content interface{}) (
	[]types.Misconfiguration, error) {
	ctx := context.TODO()

	configs := map[string]interface{}{
		fileName: content,
	}

	engine, err := policy.LoadWithData(ctx, s.policyPaths, s.dataPaths)
	if err != nil {
		return nil, xerrors.Errorf("policy load error: %w", err)
	}

	var prefixes []string
	for _, ns := range s.namespaces {
		prefixes = append(prefixes, fmt.Sprintf("%s.%s", ns, configType))
	}

	enabled, err := s.enabledNamespaces(ctx, engine, content)
	if err != nil {
		return nil, err
	}

	var results []types.Misconfiguration
	for _, ns := range enabled {
		if !underNamespaces(ns, prefixes) {
			continue
		}

		result, err := engine.Check(ctx, configs, ns)
		if err != nil {
			return nil, xerrors.Errorf("query rule: %w", err)
		}

		for _, r := range result {
			results = append(results, toMisconfiguration(configType, r))
		}
	}

	return results, nil
}

func (s Scanner) enabledNamespaces(ctx context.Context, engine *policy.Engine, content interface{}) ([]string, error) {
	allNamespaces := engine.Namespaces()

	// Pass namespaces so that Rego can refer to namespaces as data.namespaces
	nsStore := inmem.NewFromObject(map[string]interface{}{
		"namespaces": allNamespaces,
	})

	options := []func(r *rego.Rego){
		rego.Input(content),
		rego.Query("x = data.namespace.exceptions.exception"),
		rego.Compiler(engine.Compiler()),
		rego.Store(engine.Store()),
		rego.Store(nsStore),
		rego.Runtime(engine.Runtime()),
	}

	results, err := rego.New(options...).Eval(ctx)
	if err != nil {
		return nil, err
	} else if len(results) == 0 {
		return allNamespaces, nil
	}

	var disabled []string
	for _, result := range results {
		for _, configType := range result.Bindings["x"].([]interface{}) {
			ns, ok := configType.(string)
			if !ok {
				return nil, xerrors.Errorf("'exception' must return string")
			}
			disabled = append(disabled, ns)
		}
	}

	var enabled []string
	for _, ns := range allNamespaces {
		if utils.StringInSlice(ns, disabled) {
			continue
		}
		enabled = append(enabled, ns)
	}

	return enabled, nil
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

func underNamespaces(current string, namespaces []string) bool {
	// e.g.
	//  current: 'appshield',     namespaces: []string{'appshield'}     => true
	//  current: 'appshield.foo', namespaces: []string{'appshield'}     => true
	//  current: 'appshield.foo', namespaces: []string{'appshield.bar'} => false
	for _, ns := range namespaces {
		if current == ns || strings.HasPrefix(current, ns+".") {
			return true
		}
	}
	return false
}
