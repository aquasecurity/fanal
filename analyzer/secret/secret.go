package secret

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/secret"
	"github.com/aquasecurity/fanal/types"
	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
)

func init() {
	analyzer.RegisterAnalyzer(NewSecretAnalyzer())
}

const version = 1

var (
	skipFiles = []string{
		"go.mod",
		"go.sum",
		"package-lock.json",
		"Pipfile.lock",
		"Gemfile.lock",
	}
	skipDirs = []string{".git", "vendor", "node_modules"}
	skipExts = []string{".jpg", ".png", ".gif", ".doc", ".pdf", ".bin", ".svg", ".socket"}
)

// SecretAnalyzer is an analyzer for secrets
type SecretAnalyzer struct {
	scanner secret.Scanner
}

// TODO: it should take custom policies as input
func NewSecretAnalyzer() SecretAnalyzer {
	return SecretAnalyzer{
		scanner: secret.NewScanner("", []secret.Rule{}, secret.AllowList{}, secret.ExcludeBlocks{}),
	}
}

func (a SecretAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	// Do not scan binaries
	binary, err := isBinary(input.Content)
	if binary || err != nil {
		return nil, nil
	}
	fmt.Println(input.FilePath)

	content, err := io.ReadAll(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("read error %s: %w", input.FilePath, err)
	}

	result := a.scanner.Scan(secret.ScanArgs{
		FilePath: input.FilePath,
		Content:  content,
	})

	if len(result.Findings) == 0 {
		return nil, nil
	}

	return &analyzer.AnalysisResult{
		Secrets: []types.Secret{result},
	}, nil
}

func isBinary(content dio.ReadSeekerAt) (bool, error) {
	head := make([]byte, 100)
	if _, err := content.Read(head); err != nil {
		return false, err
	}
	if _, err := content.Seek(0, io.SeekStart); err != nil {
		return false, err
	}

	// cf. https://github.com/file/file/blob/f2a6e7cb7db9b5fd86100403df6b2f830c7f22ba/src/encoding.c#L151-L228
	for _, b := range head {
		if b < 7 || b == 11 || (13 < b && b < 27) || (27 < b && b < 0x20) || b == 0x7f {
			return true, nil
		}
	}

	return false, nil
}

func (a SecretAnalyzer) Required(filePath string, fi os.FileInfo) bool {
	// Skip small files
	if fi.Size() < 10 {
		return false
	}

	dir, fileName := filepath.Split(filePath)
	dir = filepath.ToSlash(dir)
	dirs := strings.Split(dir, "/")

	// Check if the directory should be skipped
	for _, skipDir := range skipDirs {
		if slices.Contains(dirs, skipDir) {
			return false
		}
	}

	// Check if the file should be skipped
	if slices.Contains(skipFiles, fileName) {
		return false
	}

	// Check if the file extension should be skipped
	ext := filepath.Ext(fileName)
	if slices.Contains(skipExts, ext) {
		return false
	}

	return true
}

func (a SecretAnalyzer) Type() analyzer.Type {
	return analyzer.TypeSecret
}

func (a SecretAnalyzer) Version() int {
	return version
}
