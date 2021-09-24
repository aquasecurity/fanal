package walker

import (
	"archive/tar"
	"debug/elf"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/xerrors"
)

const (
	opq string = ".wh..wh..opq"
	wh  string = ".wh."
)

func WalkLayerTar(layer io.Reader, analyzeFn WalkFunc) ([]string, []string, error) {
	var opqDirs, whFiles []string
	tr := tar.NewReader(layer)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, xerrors.Errorf("failed to extract the archive: %w", err)
		}

		filePath := hdr.Name
		filePath = strings.TrimLeft(filepath.Clean(filePath), "/")
		fileDir, fileName := filepath.Split(filePath)

		// e.g. etc/.wh..wh..opq
		if opq == fileName {
			opqDirs = append(opqDirs, fileDir)
			continue
		}
		// etc/.wh.hostname
		if strings.HasPrefix(fileName, wh) {
			name := strings.TrimPrefix(fileName, wh)
			fpath := filepath.Join(fileDir, name)
			whFiles = append(whFiles, fpath)
			continue
		}

		if isIgnored(filePath) {
			continue
		}
		if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink || hdr.Typeflag == tar.TypeReg {
			if hdr.FileInfo().Size() > getLargeFileSize() && !isCorrectGoBinary(tr, hdr.Name) {
				continue
			}
			err = analyzeFn(filePath, hdr.FileInfo(), tarOnceOpener(tr))
			if err != nil {
				return nil, nil, xerrors.Errorf("failed to analyze file: %w", err)
			}
		}
	}
	return opqDirs, whFiles, nil
}

func getLargeFileSize() int64 {
	const DEFAULT_LARGE_SIZE = 100000000
	v, err := strconv.ParseInt(os.Getenv("TRIVY_LARGE_FILE_SIZE"), 10, 64)
	if err != nil {
		return DEFAULT_LARGE_SIZE
	}
	return v
}

func isCorrectGoBinary(r io.Reader, fn string) bool {
	outputFilename := filepath.Join(os.TempDir(), fn)
	output, err := os.Create(outputFilename)
	if err != nil {
		return false
	}
	defer func() {
		output.Close()
		os.Remove(outputFilename)
	}()
	if _, err := io.Copy(output, r); err != nil {
		return false
	}
	f, err := elf.NewFile(output)
	if err != nil {
		return false
	}
	if sect := f.Section(".go.buildinfo"); sect != nil {
		return true
	}
	return false
}
// tarOnceOpener reads a file once and the content is shared so that some analyzers can use the same data
func tarOnceOpener(r io.Reader) func() ([]byte, error) {
	var once sync.Once
	var b []byte
	var err error

	return func() ([]byte, error) {
		once.Do(func() {
			b, err = ioutil.ReadAll(r)
		})
		if err != nil {
			return nil, xerrors.Errorf("unable to read tar file: %w", err)
		}
		return b, nil
	}
}
