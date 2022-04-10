package misconf

import (
	"context"
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"

	yaml "github.com/goccy/go-yaml"
	"github.com/liamg/memoryfs"
	"github.com/open-policy-agent/opa/rego"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners"
	cfscanner "github.com/aquasecurity/defsec/pkg/scanners/cloudformation"
	cfparser "github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	dfscanner "github.com/aquasecurity/defsec/pkg/scanners/dockerfile"
	dfparser "github.com/aquasecurity/defsec/pkg/scanners/dockerfile/parser"
	k8sscanner "github.com/aquasecurity/defsec/pkg/scanners/kubernetes"
	k8sparser "github.com/aquasecurity/defsec/pkg/scanners/kubernetes/parser"
	tfscanner "github.com/aquasecurity/defsec/pkg/scanners/terraform"
	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/handler"
	"github.com/aquasecurity/fanal/log"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	handler.RegisterPostHandlerInit(types.MisconfPostHandler, newMisconfPostHandler)
}

var (
	//go:embed detection.rego
	defaultDetectionModule string

	// TODO(liam): Want DefSec to return these values.
	typeMap = map[string]string{
		types.Terraform:      "Terraform Security Check",
		types.CloudFormation: "CloudFormation Security Check",
		types.Dockerfile:     "Dockerfile Security Check",
		types.Kubernetes:     "Kubernetes Security Check",
	}
)

const version = 1

type misconfPostHandler struct {
	scanners map[string]scanners.Scanner
}

func newMisconfPostHandler(_ artifact.Option, _ config.ScannerOption) (handler.PostHandler, error) {
	return misconfPostHandler{
		scanners: map[string]scanners.Scanner{
			types.Terraform: tfscanner.New(),

			// The given memoryfs contains only CloudFormation files. DefSec doesn't need to check if each file is required.
			types.CloudFormation: cfscanner.New(cfscanner.OptionWithParser(
				cfparser.New(cfparser.OptionWithSkipRequired(true)))),

			// The given memoryfs contains only Dockerfile. DefSec doesn't need to check if each file is required.
			types.Dockerfile: dfscanner.NewScanner(dfscanner.OptionWithParser(
				dfparser.New(dfparser.OptionWithSkipRequired(true)))),

			// The given memoryfs contains only Kubernetes manifests. DefSec doesn't need to check if each file is required.
			types.Kubernetes: k8sscanner.NewScanner(k8sscanner.OptionWithParser(
				k8sparser.New(k8sparser.OptionWithSkipRequired(true)))),
		},
	}, nil
}

// Handle detects misconfigurations.
func (h misconfPostHandler) Handle(ctx context.Context, result *analyzer.AnalysisResult, blob *types.BlobInfo) error {
	files, ok := result.Files[h.Type()]
	if !ok {
		return nil
	}

	mapMemoryFS := map[string]*memoryfs.FS{
		types.Terraform:      memoryfs.New(),
		types.CloudFormation: memoryfs.New(),
		types.Dockerfile:     memoryfs.New(),
		types.Kubernetes:     memoryfs.New(),
	}

	for _, file := range files {
		var unmarshalFunc func([]byte, any) error
		switch file.Type {
		case types.JSON:
			unmarshalFunc = json.Unmarshal
		case types.YAML:
			unmarshalFunc = yaml.Unmarshal
		}

		if file.Type == types.JSON || file.Type == types.YAML {
			var parsed any
			if err := unmarshalFunc(file.Content, &parsed); err != nil {
				log.Logger.Debugf("Parse error %s: %s", file.Path, err)
			}

			// Detect config types such as CloudFormation and Kubernetes.
			configType, err := detectConfigType(ctx, parsed)
			if err != nil {
				return xerrors.Errorf("unable to detect config type %s: %w", file.Path, err)
			} else if configType == "" {
				// Skip unknown config types
				continue
			}

			// Replace with more detailed config type
			file.Type = configType
		}

		if memfs, ok := mapMemoryFS[file.Type]; ok {
			if err := memfs.MkdirAll(filepath.Dir(file.Path), os.ModePerm); err != nil {
				return xerrors.Errorf("memoryfs mkdir error: %w", err)
			}
			if err := memfs.WriteFile(file.Path, file.Content, os.ModePerm); err != nil {
				return xerrors.Errorf("memoryfs write error: %w", err)
			}
		}
	}

	var misconfs []types.Misconfiguration
	for t, scanner := range h.scanners {
		results, err := scanner.ScanFS(ctx, mapMemoryFS[t], ".")
		if err != nil {
			return xerrors.Errorf("scan config error: %w", err)
		}

		misconfs = append(misconfs, resultsToMisconf(t, results)...)
	}

	// Add misconfigurations
	blob.Misconfigurations = misconfs

	return nil
}

func (h misconfPostHandler) Version() int {
	return version
}

func (h misconfPostHandler) Type() types.HandlerType {
	return types.MisconfPostHandler
}

func (h misconfPostHandler) Priority() int {
	return types.MisconfPostHandlerPriority
}

// TODO(liam): move to DefSec; no need to use Rego.
func detectConfigType(ctx context.Context, input interface{}) (string, error) {
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

func resultsToMisconf(configType string, results scan.Results) []types.Misconfiguration {
	misconfs := map[string]types.Misconfiguration{}

	for _, result := range results {
		flattened := result.Flatten()
		misconfResult := types.MisconfResult{
			Message: flattened.Description,
			PolicyMetadata: types.PolicyMetadata{
				ID:                 flattened.RuleID,
				Type:               typeMap[configType],
				Title:              flattened.RuleSummary,
				Description:        flattened.Impact,
				Severity:           string(flattened.Severity),
				RecommendedActions: flattened.Resolution,
				References:         flattened.Links,
			},
			IacMetadata: types.IacMetadata{
				Resource:  flattened.Resource,
				Provider:  flattened.RuleProvider.DisplayName(),
				Service:   flattened.RuleService,
				StartLine: flattened.Location.StartLine,
				EndLine:   flattened.Location.EndLine,
			},
		}

		//var filePath = "unknown"
		//if flattened.Location.Filename != "" {
		//	filePath, err = filepath.Rel(rootDir, flattened.Location.Filename)
		//	if err != nil {
		//		return nil, xerrors.Errorf("filepath rel, root: [%s], result: [%s] %w", rootDir, flattened.Location.Filename, err)
		//	}
		//}

		// TODO(liam): Need file names even when the check is passed
		filePath := flattened.Location.Filename
		misconf, ok := misconfs[filePath]
		if !ok {
			misconf = types.Misconfiguration{
				FileType: configType,
				FilePath: filePath,
			}
		}

		// TODO(liam): support warnings
		switch flattened.Status {
		case scan.StatusPassed:
			misconf.Successes = append(misconf.Successes, misconfResult)
		case scan.StatusIgnored:
			misconf.Exceptions = append(misconf.Exceptions, misconfResult)
		case scan.StatusFailed:
			misconf.Failures = append(misconf.Failures, misconfResult)
		}
		misconfs[filePath] = misconf
	}

	return types.ToMisconfigurations(misconfs)
}
