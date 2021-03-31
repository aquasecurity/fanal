package policy

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/loader"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/open-policy-agent/opa/version"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

const metadataSymbol = "__rego_metadata__"

// Engine represents the policy engine.
type Engine struct {
	modules  map[string]*ast.Module
	compiler *ast.Compiler
	store    storage.Store
	policies map[string]string
	docs     map[string]string
}

// Load returns an Engine after loading all of the specified policies and data paths.
func Load(policyPaths []string, dataPaths []string) (*Engine, error) {
	policies, err := loader.AllRegos(policyPaths)
	if err != nil {
		return nil, xerrors.Errorf("load: %w", err)
	} else if len(policies.Modules) == 0 {
		return nil, xerrors.Errorf("no policies found in %v", policyPaths)
	}

	compiler, err := policies.Compiler()
	if err != nil {
		return nil, xerrors.Errorf("get compiler: %w", err)
	}

	policyContents := make(map[string]string)
	for path, module := range policies.ParsedModules() {
		path = filepath.Clean(path)
		path = filepath.ToSlash(path)

		policyContents[path] = module.String()
	}

	modules := policies.ParsedModules()

	store, docs, err := loadData(dataPaths, allNamespaces(modules))
	if err != nil {
		return nil, xerrors.Errorf("unable to load data: %w", err)
	}

	return &Engine{
		modules:  modules,
		compiler: compiler,
		policies: policyContents,
		store:    store,
		docs:     docs,
	}, nil
}

func allNamespaces(modules map[string]*ast.Module) []string {
	uniq := map[string]struct{}{}
	for _, module := range modules {
		namespace := strings.Replace(module.Package.Path.String(), "data.", "", 1)
		uniq[namespace] = struct{}{}
	}

	var namespaces []string
	for ns := range uniq {
		namespaces = append(namespaces, ns)
	}
	return namespaces
}

func loadData(dataPaths, namespaces []string) (storage.Store, map[string]string, error) {
	// FilteredPaths will recursively find all file paths that contain a valid document
	// extension from the given list of data paths.
	allDocumentPaths, err := loader.FilteredPaths(dataPaths, func(abspath string, info os.FileInfo, depth int) bool {
		if info.IsDir() {
			return false
		}
		ext := strings.ToLower(filepath.Ext(info.Name()))
		return !utils.StringInSlice(ext, []string{".yaml", ".yml", ".json"})
	})
	if err != nil {
		return nil, nil, xerrors.Errorf("filter data paths: %w", err)
	}

	documents, err := loader.NewFileLoader().All(allDocumentPaths)
	if err != nil {
		return nil, nil, xerrors.Errorf("load documents: %w", err)
	}

	// Pass all namespaces so that Rego rule can refer to namespaces as data.namespaces
	documents.Documents["namespaces"] = namespaces

	store, err := documents.Store()
	if err != nil {
		return nil, nil, xerrors.Errorf("get documents store: %w", err)
	}

	documentContents := make(map[string]string)
	for _, documentPath := range allDocumentPaths {
		contents, err := ioutil.ReadFile(documentPath)
		if err != nil {
			return nil, nil, xerrors.Errorf("read file: %w", err)
		}

		documentPath = filepath.Clean(documentPath)
		documentPath = filepath.ToSlash(documentPath)
		documentContents[documentPath] = string(contents)
	}

	return store, documentContents, nil
}

// Check executes all of the loaded policies against the input and returns the results.
func (e *Engine) Check(ctx context.Context, configType, filePath string, config interface{}, namespaces []string) (
	types.Misconfiguration, error) {
	// It is possible for a configuration to have multiple configurations. An example of this
	// are multi-document yaml files where a single filepath represents multiple configs.
	//
	// If the current configuration contains multiple configurations, evaluate each policy
	// independent from one another and aggregate the results under the same file name.
	configs := []interface{}{config}
	if subconfigs, ok := config.([]interface{}); ok {
		configs = subconfigs
	}

	result, err := e.check(ctx, configType, filePath, configs, namespaces)
	if err != nil {
		return types.Misconfiguration{}, xerrors.Errorf("check: %w", err)
	}

	return result, nil
}

// Compiler returns the compiler from the loaded policies.
func (e *Engine) Compiler() *ast.Compiler {
	return e.compiler
}

// Store returns the store from the loaded documents.
func (e *Engine) Store() storage.Store {
	return e.store
}

// Modules returns the modules from the loaded policies.
func (e *Engine) Modules() map[string]*ast.Module {
	return e.modules
}

// Runtime returns the runtime of the engine.
func (e *Engine) Runtime() *ast.Term {
	env := ast.NewObject()
	for _, pair := range os.Environ() {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 1 {
			env.Insert(ast.StringTerm(parts[0]), ast.NullTerm())
		} else if len(parts) > 1 {
			env.Insert(ast.StringTerm(parts[0]), ast.StringTerm(parts[1]))
		}
	}

	obj := ast.NewObject()
	obj.Insert(ast.StringTerm("env"), ast.NewTerm(env))
	obj.Insert(ast.StringTerm("version"), ast.StringTerm(version.Version))
	obj.Insert(ast.StringTerm("commit"), ast.StringTerm(version.Vcs))

	return ast.NewTerm(obj)
}

func (e *Engine) check(ctx context.Context, configType, filePath string, configs []interface{}, namespaces []string) (
	types.Misconfiguration, error) {
	misconf := types.Misconfiguration{
		FilePath: filePath,
		FileType: configType,
	}
	for _, module := range e.Modules() {
		currentNamespace := strings.Replace(module.Package.Path.String(), "data.", "", 1)
		if !underNamespaces(currentNamespace, configType, namespaces) {
			continue
		}

		metadata, err := e.queryMetadata(ctx, currentNamespace)
		if err != nil {
			return types.Misconfiguration{}, err
		}

		var rules []string
		for r := range module.Rules {
			currentRule := module.Rules[r].Head.Name.String()
			if isFailure(currentRule) || isWarning(currentRule) {
				rules = append(rules, currentRule)
			}
		}

		for _, rule := range rules {
			for _, config := range configs {
				successes, warnings, failures, exceptions, err := e.checkRule(ctx, currentNamespace, rule, config, metadata)
				if err != nil {
					return types.Misconfiguration{}, xerrors.Errorf("check rule: %w", err)
				}
				misconf.Successes = append(misconf.Successes, successes...)
				misconf.Warnings = append(misconf.Warnings, warnings...)
				misconf.Failures = append(misconf.Failures, failures...)
				misconf.Exceptions = append(misconf.Exceptions, exceptions...)
			}
		}
	}

	misconf.Successes = uniqueSuccesses(misconf.Successes)
	return misconf, nil
}

func (e *Engine) checkRule(ctx context.Context, namespace, rule string, config interface{}, metadata types.MisconfMetadata) (
	[]types.MisconfResult, []types.MisconfResult, []types.MisconfResult, []types.MisconfResult, error) {

	exception, err := e.namespaceExceptions(ctx, namespace, config)
	if err != nil {
		return nil, nil, nil, nil, xerrors.Errorf("namespace exceptions: %w", err)
	} else if len(exception) > 0 {
		return nil, nil, nil, exception, nil
	}

	exception, err = e.ruleExceptions(ctx, namespace, rule, config)
	if err != nil {
		return nil, nil, nil, nil, xerrors.Errorf("rule exceptions: %w", err)
	} else if len(exception) > 0 {
		return nil, nil, nil, exception, nil
	}

	ruleQuery := fmt.Sprintf("data.%s.%s", namespace, rule)
	ruleQueryResult, err := e.query(ctx, config, ruleQuery)
	if err != nil {
		return nil, nil, nil, nil, xerrors.Errorf("query rule: %w", err)
	}

	var successes, failures, warnings []types.MisconfResult
	for _, ruleResult := range ruleQueryResult.results {
		ruleResult.Namespace = namespace
		ruleResult.MisconfMetadata = metadata

		if ruleResult.Message == "" {
			successes = append(successes, ruleResult)
		} else if isFailure(rule) {
			failures = append(failures, ruleResult)
		} else {
			warnings = append(warnings, ruleResult)
		}
	}

	return successes, warnings, failures, nil, nil
}

func (e *Engine) namespaceExceptions(ctx context.Context, namespace string, config interface{}) ([]types.MisconfResult, error) {
	exceptionQuery := fmt.Sprintf("data.namespace.exceptions.exception[_] == %q", namespace)
	exceptionQueryResult, err := e.query(ctx, config, exceptionQuery)
	if err != nil {
		return nil, xerrors.Errorf("query namespace exception: %w", err)
	}

	var exceptions []types.MisconfResult
	for _, exceptionResult := range exceptionQueryResult.results {
		// When an exception is found, set the message of the exception
		// to the query that triggered the exception so that it is known
		// which exception was triggered.
		if exceptionResult.Message == "" {
			exceptionResult.Namespace = namespace
			exceptionResult.Message = exceptionQuery
			exceptions = append(exceptions, exceptionResult)
		}
	}
	return exceptions, nil
}

func (e *Engine) ruleExceptions(ctx context.Context, namespace, rule string, config interface{}) ([]types.MisconfResult, error) {
	exceptionQuery := fmt.Sprintf("data.%s.exception[_][_] == %q", namespace, removeRulePrefix(rule))
	exceptionQueryResult, err := e.query(ctx, config, exceptionQuery)
	if err != nil {
		return nil, xerrors.Errorf("query rule exception: %w", err)
	}

	var exceptions []types.MisconfResult
	for _, exceptionResult := range exceptionQueryResult.results {
		// When an exception is found, set the message of the exception
		// to the query that triggered the exception so that it is known
		// which exception was triggered.
		if exceptionResult.Message == "" {
			exceptionResult.Namespace = namespace
			exceptionResult.Message = exceptionQuery
			exceptions = append(exceptions, exceptionResult)
		}
	}
	return exceptions, nil
}

// query is a low-level method that has no notion of a failed policy or successful policy. // It only returns the result of executing a single query against the input.
//
// Example queries could include:
// data.main.deny to query the deny rule in the main namespace
// data.main.warn to query the warn rule in the main namespace
func (e *Engine) query(ctx context.Context, input interface{}, query string) (queryResult, error) {
	stdout := topdown.NewBufferTracer()
	options := []func(r *rego.Rego){
		rego.Input(input),
		rego.Query(query),
		rego.Compiler(e.Compiler()),
		rego.Store(e.Store()),
		rego.Runtime(e.Runtime()),
		rego.QueryTracer(stdout),
	}
	resultSet, err := rego.New(options...).Eval(ctx)
	if err != nil {
		return queryResult{}, xerrors.Errorf("evaluating policy: %w", err)
	}

	// After the evaluation of the policy, the results of the trace (stdout) will be populated
	// for the query. Once populated, format the trace results into a human readable format.
	buf := new(bytes.Buffer)
	topdown.PrettyTrace(buf, *stdout)
	var traces []string
	for _, line := range strings.Split(buf.String(), "\n") {
		if len(line) > 0 {
			traces = append(traces, line)
		}
	}

	var results []types.MisconfResult
	for _, result := range resultSet {
		for _, expression := range result.Expressions {

			// Rego rules that are intended for evaluation should return a slice of values.
			// For example, deny[msg] or violation[{"msg": msg}].
			//
			// When an expression does not have a slice of values, the expression did not
			// evaluate to true, and no message was returned.
			var expressionValues []interface{}
			if _, ok := expression.Value.([]interface{}); ok {
				expressionValues = expression.Value.([]interface{})
			}
			if len(expressionValues) == 0 {
				results = append(results, types.MisconfResult{})
				continue
			}

			for _, v := range expressionValues {
				switch val := v.(type) {

				// Policies that only return a single string (e.g. deny[msg])
				case string:
					results = append(results, types.MisconfResult{
						Message: val,
					})

				// Policies that return metadata (e.g. deny[{"msg": msg}])
				case map[string]interface{}:
					res, err := newResult(val)
					if err != nil {
						return queryResult{}, xerrors.Errorf("new result: %w", err)
					}

					results = append(results, res)
				}
			}
		}
	}

	return queryResult{
		query:   query,
		results: results,
		traces:  traces,
	}, nil
}

func (e *Engine) queryMetadata(ctx context.Context, namespace string) (types.MisconfMetadata, error) {
	query := fmt.Sprintf("x = data.%s.__rego_metadata__", namespace)
	options := []func(r *rego.Rego){
		rego.Query(query),
		rego.Compiler(e.Compiler()),
		rego.Store(e.Store()),
	}
	resultSet, err := rego.New(options...).Eval(ctx)
	if err != nil {
		return types.MisconfMetadata{}, xerrors.Errorf("evaluating '__rego_metadata__': %w", err)
	}

	// Set default values
	metadata := types.MisconfMetadata{
		ID:       "N/A",
		Type:     "N/A",
		Title:    "N/A",
		Severity: "UNKNOWN",
	}

	if len(resultSet) == 0 {
		return metadata, nil
	}

	result, ok := resultSet[0].Bindings["x"].(map[string]interface{})
	if !ok {
		return types.MisconfMetadata{}, xerrors.New("'__rego_metadata__' must be map")
	}

	if err = mapstructure.Decode(result, &metadata); err != nil {
		return types.MisconfMetadata{}, xerrors.Errorf("decode error: %w", err)
	}

	return metadata, nil
}

func isWarning(rule string) bool {
	warningRegex := regexp.MustCompile("^warn(_[a-zA-Z0-9]+)*$")
	return warningRegex.MatchString(rule)
}

func isFailure(rule string) bool {
	failureRegex := regexp.MustCompile("^(deny|violation)(_[a-zA-Z0-9]+)*$")
	return failureRegex.MatchString(rule)
}

// When matching rules for exceptions, only the name of the rule
// is queried, so the severity prefix must be removed.
func removeRulePrefix(rule string) string {
	rule = strings.TrimPrefix(rule, "violation_")
	rule = strings.TrimPrefix(rule, "deny_")
	rule = strings.TrimPrefix(rule, "warn_")

	return rule
}

func uniqueSuccesses(successes []types.MisconfResult) []types.MisconfResult {
	uniq := map[string]types.MisconfResult{}
	for _, success := range successes {
		uniq[success.ID+":"+success.Namespace] = success
	}

	var uniqSuccesses []types.MisconfResult
	for _, s := range uniq {
		uniqSuccesses = append(uniqSuccesses, s)
	}
	return uniqSuccesses
}

func underNamespaces(current, configType string, namespaces []string) bool {
	// e.g.
	//  current: 'main.kubernetes',     configType: kubernetes, namespaces: []string{'main'} => true
	//  current: 'main.kubernetes.foo', configType: kubernetes, namespaces: []string{'main'} => true
	//  current: 'main.docker.foo',     configType: kubernetes, namespaces: []string{'main'} => false
	for _, ns := range namespaces {
		ns += fmt.Sprintf(".%s", configType)
		if current == ns || strings.HasPrefix(current, ns+".") {
			return true
		}
	}
	return false
}

// queryResult describes the result of evaluting a query.
type queryResult struct {

	// Query is the fully qualified query that was used
	// to determine the result. Ex: (data.main.deny)
	query string

	// Results are the individual results of the query.
	// When querying data.main.deny, multiple deny rules can
	// exist, producing multiple results.
	results []types.MisconfResult

	// Traces represents a single trace of how the query was
	// evaluated. Each trace value is a trace line.
	traces []string
}

func newResult(r map[string]interface{}) (types.MisconfResult, error) {
	if _, ok := r["msg"]; !ok {
		return types.MisconfResult{}, xerrors.Errorf("rule missing 'msg' field: %v", r)
	}

	msg, ok := r["msg"].(string)
	if !ok {
		return types.MisconfResult{}, xerrors.Errorf("'msg' field must be string: %v", r)
	}

	return types.MisconfResult{
		Message: strings.TrimSpace(msg),
	}, nil
}
