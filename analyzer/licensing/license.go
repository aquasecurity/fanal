package licensing

import (
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/licensing"
	"github.com/aquasecurity/fanal/types"
	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"
)

const version = 1

var skipExts = []string{
	".jpg", ".png", ".gif", ".doc", ".pdf", ".bin", ".svg", ".socket", ".deb", ".rpm",
	".zip", ".gz", ".gzip", ".tar", ".pyc",
}

type ScannerOption struct {
	ConfigPath string
}

// LicenseAnalyzer is an analyzer for licenses
type LicenseAnalyzer struct {
	scanner licensing.Scanner
}

func RegisterLicenseScanner(opt ScannerOption) error {
	a, err := newLicenseScanner(opt.ConfigPath)
	if err != nil {
		return xerrors.Errorf("license scanner init error: %w", err)
	}
	analyzer.RegisterAnalyzer(a)
	return nil
}

func newLicenseScanner(configPath string) (LicenseAnalyzer, error) {
	s, err := licensing.NewScanner(configPath)
	if err != nil {
		return LicenseAnalyzer{}, xerrors.Errorf("license scanner error: %w", err)
	}
	return LicenseAnalyzer{
		scanner: s,
	}, nil
}

func (a LicenseAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {

	// need files to be text based, readable files
	readable, err := isHumanReadable(input.Content, input.Info.Size())
	if err != nil || !readable {
		return nil, nil
	}

	content, err := io.ReadAll(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("read error %s: %w", input.FilePath, err)
	}

	filePath := input.FilePath
	// Files extracted from the image have an empty input.Dir.
	// Also, paths to these files do not have "/" prefix.
	// We need to add a "/" prefix to properly filter paths from the config file.
	if input.Dir == "" { // add leading `/` for files extracted from image
		filePath = fmt.Sprintf("/%s", filePath)
	}

	result := a.scanner.Scan(licensing.ScanArgs{
		FilePath: filePath,
		Content:  content,
	})

	if len(result.Findings) == 0 {
		return nil, nil
	}

	return &analyzer.AnalysisResult{
		Files: map[types.HandlerType][]types.File{
			// It will be passed to license post handler
			types.LicensePostHandler: {
				{
					Type:    types.License,
					Path:    input.FilePath,
					Content: content,
				},
			},
		},
	}, nil
}

func (a LicenseAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	if slices.Contains(skipExts, ext) {
		return false
	}

	return true
}

func isHumanReadable(content dio.ReadSeekerAt, fileSize int64) (bool, error) {
	headSize := int(math.Min(float64(fileSize), 300))
	head := make([]byte, headSize)
	if _, err := content.Read(head); err != nil {
		return false, err
	}
	if _, err := content.Seek(0, io.SeekStart); err != nil {
		return false, err
	}

	// cf. https://github.com/file/file/blob/f2a6e7cb7db9b5fd86100403df6b2f830c7f22ba/src/encoding.c#L151-L228
	for _, b := range head {
		if b < 7 || b == 11 || (13 < b && b < 27) || (27 < b && b < 0x20) || b == 0x7f {
			return false, nil
		}
	}

	return true, nil
}

func (a LicenseAnalyzer) Type() analyzer.Type {
	return analyzer.TypeLicense
}

func (a LicenseAnalyzer) Version() int {
	return version
}
