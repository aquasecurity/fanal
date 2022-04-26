package misconf

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aquasecurity/defsec/pkg/detection"

	"github.com/liamg/memoryfs"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners"
	cfscanner "github.com/aquasecurity/defsec/pkg/scanners/cloudformation"
	dfscanner "github.com/aquasecurity/defsec/pkg/scanners/dockerfile"
	k8sscanner "github.com/aquasecurity/defsec/pkg/scanners/kubernetes"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
	tfscanner "github.com/aquasecurity/defsec/pkg/scanners/terraform"
	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/handler"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	handler.RegisterPostHandlerInit(types.MisconfPostHandler, newMisconfPostHandler)
}

const version = 1

type misconfPostHandler struct {
	scanners map[string]scanners.Scanner
}

func newMisconfPostHandler(artifactOpt artifact.Option) (handler.PostHandler, error) {
	opt := artifactOpt.MisconfScannerOption

	opts := []options.ScannerOption{
		options.ScannerWithSkipRequiredCheck(true),
	}

	if opt.Trace {
		opts = append(opts, options.ScannerWithPerResultTracing(true))
	}

	if len(opt.PolicyPaths) > 0 {
		opts = append(opts, options.ScannerWithPolicyDirs(opt.PolicyPaths...))
	}

	if len(opt.DataPaths) > 0 {
		opts = append(opts, options.ScannerWithDataDirs(opt.DataPaths...))
	}

	if len(opt.Namespaces) > 0 {
		opts = append(opts, options.ScannerWithPolicyNamespaces(opt.Namespaces...))
	}

	return misconfPostHandler{
		scanners: map[string]scanners.Scanner{
			types.Terraform:      tfscanner.New(opts...),
			types.CloudFormation: cfscanner.New(opts...),
			types.Dockerfile:     dfscanner.NewScanner(opts...),
			types.Kubernetes:     k8sscanner.NewScanner(opts...),
		},
	}, nil
}

var enabledDefsecTypes = map[detection.FileType]string{
	detection.FileTypeCloudFormation: types.CloudFormation,
	detection.FileTypeTerraform:      types.Terraform,
	detection.FileTypeDockerfile:     types.Dockerfile,
	detection.FileTypeKubernetes:     types.Kubernetes,
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

		for defsecType, localType := range enabledDefsecTypes {

			buffer := bytes.NewReader(file.Content)
			if !detection.IsType(file.Path, buffer, defsecType) {
				continue
			}
			// Replace with more detailed config type
			file.Type = localType

			if memfs, ok := mapMemoryFS[file.Type]; ok {
				if err := memfs.MkdirAll(filepath.Dir(file.Path), os.ModePerm); err != nil {
					return xerrors.Errorf("memoryfs mkdir error: %w", err)
				}
				if err := memfs.WriteFile(file.Path, file.Content, os.ModePerm); err != nil {
					return xerrors.Errorf("memoryfs write error: %w", err)
				}
			}
		}
	}

	var misconfs []types.Misconfiguration
	for t, scanner := range h.scanners {
		results, err := scanner.ScanFS(ctx, mapMemoryFS[t], ".")
		if err != nil {
			return xerrors.Errorf("scan config error: %w", err)
		}

		misconfs = append(misconfs, resultsToMisconf(t, scanner.Name(), results)...)
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

func resultsToMisconf(configType string, scannerName string, results scan.Results) []types.Misconfiguration {
	misconfs := map[string]types.Misconfiguration{}

	for _, result := range results {
		flattened := result.Flatten()
		misconfResult := types.MisconfResult{
			Message: flattened.Description,
			PolicyMetadata: types.PolicyMetadata{
				ID:                 flattened.RuleID,
				Type:               fmt.Sprintf("%s Security Check", scannerName),
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
			Traces: result.Traces(),
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
