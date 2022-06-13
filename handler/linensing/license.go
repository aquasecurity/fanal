package linensing

import (
	"context"
	"os"
	"path/filepath"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/handler"
	"github.com/aquasecurity/fanal/licensing"
	"github.com/aquasecurity/fanal/types"
	"github.com/liamg/memoryfs"
	"golang.org/x/xerrors"
)

func init() {
	handler.RegisterPostHandlerInit(types.LicensePostHandler, newLicensePostHandler)
}

const version = 1

type licensePostHandler struct {
	scanner licensing.Scanner
}

func newLicensePostHandler(artifactOpt artifact.Option) (handler.PostHandler, error) {

	scanner, err := licensing.NewScanner(artifactOpt.LicenseScannerOption.ConfigPath)
	if err != nil {
		return nil, err
	}

	return licensePostHandler{
		scanner: scanner,
	}, nil
}

func (h licensePostHandler) Handle(_ context.Context, result *analyzer.AnalysisResult, blob *types.BlobInfo) error {
	files, ok := result.Files[h.Type()]
	if !ok {
		return nil
	}

	licenseFS := memoryfs.New()
	for _, file := range files {
		if filepath.Dir(file.Path) != "." {
			if err := licenseFS.MkdirAll(filepath.Dir(file.Path), os.ModePerm); err != nil {
				return xerrors.Errorf("licensingfs mkdir error: %w", err)
			}
		}
		if err := licenseFS.WriteFile(file.Path, file.Content, os.ModePerm); err != nil {
			return xerrors.Errorf("licensingfs write error: %w", err)
		}
	}

	licenseFiles, err := h.scanner.ScanFS(licenseFS)
	if err != nil {
		return xerrors.Errorf("licensing scanning errors: %w", err)
	}

	blob.Licenses = licenseFiles

	return nil

}

func (h licensePostHandler) Type() types.HandlerType {
	return types.LicensePostHandler
}

func (h licensePostHandler) Version() int {
	return version
}

func (h licensePostHandler) Priority() int {
	return types.LicensePostHandlerPriority
}
