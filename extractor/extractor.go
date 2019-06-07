package extractor

import (
	"context"
	"io"
	"os"

	"github.com/pkg/errors"
)

var (
	// ErrCouldNotExtract occurs when an extraction fails.
	ErrCouldNotExtract = errors.New("Could not extract the archive")
)

type FileMap map[string]FileData
type FileData struct {
	Body     []byte
	FileMode os.FileMode
}

type Extractor interface {
	Extract(ctx context.Context, imageName string, filenames []string) (FileMap, error)
	ExtractFromFile(ctx context.Context, r io.Reader, filenames []string) (FileMap, error)
}
