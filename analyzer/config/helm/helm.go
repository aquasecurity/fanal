package helm

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	"golang.org/x/xerrors"
)

const version = 1

type ConfigAnalyzer struct {
	filePattern *regexp.Regexp
}

func NewConfigAnalyzer(filePattern *regexp.Regexp) ConfigAnalyzer {
	return ConfigAnalyzer{
		filePattern: filePattern,
	}
}

func (a ConfigAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	b, err := io.ReadAll(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("failed to read %s: %w", input.FilePath, err)
	}

	return &analyzer.AnalysisResult{
		Files: map[types.HandlerType][]types.File{
			// it will be passed to misconfig post handler
			types.MisconfPostHandler: {
				{
					Type:    types.Helm,
					Path:    input.FilePath,
					Content: b,
				},
			},
		},
	}, nil
}

func (a ConfigAnalyzer) Required(filePath string, _ os.FileInfo, readerOpener analyzer.Opener) bool {
	if a.filePattern != nil && a.filePattern.MatchString(filePath) {
		return true
	}

	if isArchive(filePath) {
		reader, err := readerOpener()
		if err != nil {
			return false
		}
		return isHelmChart(filePath, reader)
	}

	ext := filepath.Ext(filePath)
	for _, acceptable := range []string{".tpl", ".json", ".yaml"} {
		if strings.EqualFold(ext, acceptable) {
			return true
		}
	}

	name := filepath.Base(filePath)
	for _, acceptable := range []string{"NOTES.txt", "Chart.yaml", ".helmignore"} {
		if strings.EqualFold(name, acceptable) {
			return true
		}
	}

	return false
}

func (ConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeHelm
}

func (ConfigAnalyzer) Version() int {
	return version
}

func isHelmChart(path string, file io.ReadCloser) bool {

	var err error
	var fr = file

	if isZip(path) {
		if fr, err = gzip.NewReader(file); err != nil {
			return false
		}
	}
	tr := tar.NewReader(fr)

	for {
		header, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return false
		}

		if header.Typeflag == tar.TypeReg && strings.HasSuffix(header.Name, "Chart.yaml") {
			return true
		}
	}
	return false
}

func isArchive(path string) bool {
	if strings.HasSuffix(path, ".tar") ||
		strings.HasSuffix(path, ".tgz") ||
		strings.HasSuffix(path, ".tar.gz") {
		return true
	}
	return false
}

func isZip(path string) bool {
	if strings.HasSuffix(path, ".tgz") ||
		strings.HasSuffix(path, ".tar.gz") {
		return true
	}
	return false
}
