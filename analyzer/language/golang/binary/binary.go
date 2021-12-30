package binary

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/aquasecurity/go-dep-parser/pkg/golang/binary"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/language"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&gobinaryLibraryAnalyzer{})
}

const version = 1

type gobinaryLibraryAnalyzer struct{}

func (a gobinaryLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	libs, err := binary.Parse(input.Content)
	if errors.Is(err, binary.ErrUnrecognizedExe) || errors.Is(err, binary.ErrNonGoBinary) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("go binary parse error: %w", err)
	}

	return language.ToAnalysisResult(types.GoBinary, input.FilePath, "", libs), nil
}

func (a gobinaryLibraryAnalyzer) Required(_ string, fileInfo os.FileInfo) bool {
	mode := fileInfo.Mode()
	if !mode.IsRegular() {
		return false
	}

	// Check executable file
	if mode.Perm()&0o111 != 0 {
		return true
	}
	return false
}

func (a gobinaryLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGoBinary
}

func (a gobinaryLibraryAnalyzer) Version() int {
	return version
}
