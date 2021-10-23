package walker

import (
	"archive/tar"
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/xerrors"
)

const (
	opq string = ".wh..wh..opq"
	wh  string = ".wh."
)

type LayerTar struct {
	walker
}

func NewLayerTar(skipFiles, skipDirs []string) LayerTar {
	return LayerTar{
		walker: newWalker(skipFiles, skipDirs),
	}
}

func (w LayerTar) Walk(layer io.Reader, analyzeFn WalkFunc) ([]string, []string, error) {
	var opqDirs, whFiles, skipDirs []string
	tr := tar.NewReader(layer)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
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

		switch hdr.Typeflag {
		case tar.TypeDir:
			if w.shouldSkipDir(filePath) {
				skipDirs = append(skipDirs, filePath)
				continue
			}
		case tar.TypeSymlink, tar.TypeLink, tar.TypeReg:
			if w.shouldSkipFile(filePath) {
				continue
			}
		default:
			continue
		}

		if underSkippedDir(filePath, skipDirs) {
			continue
		}

		// A symbolic/hard link or regular file will reach here.
		err = analyzeFn(filePath, hdr.FileInfo(), w.fileWithTarOpener(hdr.FileInfo(), tr))
		if err != nil {
			return nil, nil, xerrors.Errorf("failed to analyze file: %w", err)
		}
	}
	return opqDirs, whFiles, nil
}

func underSkippedDir(filePath string, skipDirs []string) bool {
	for _, skipDir := range skipDirs {
		rel, err := filepath.Rel(skipDir, filePath)
		if err != nil {
			return false
		}
		if !strings.HasPrefix(rel, "../") {
			return true
		}
	}
	return false
}

func (w *walker) fileWithTarOpener(fi os.FileInfo, r io.Reader) func() (io.ReadCloser, func() error, error) {

	var once sync.Once
	var b []byte
	var tempFilePath string
	var tempDirPath string
	var err error

	return func() (io.ReadCloser, func() error, error) {
		once.Do(func() {
			if fi.Size() > N {
				var f *os.File
				tempDirPath, err = ioutil.TempDir("", "trivy-*")
				f, err = os.CreateTemp(tempDirPath, "trivy-*")
				_, err = io.Copy(f, r)
				tempFilePath = f.Name()
			} else {
				b, err = io.ReadAll(r)
			}
		})
		if err != nil {
			return nil, nil, xerrors.Errorf("unable to read the file: %w", err)
		}

		if fi.Size() > N {
			f, err := os.Open(tempFilePath)
			if err != nil {
				return nil, nil, xerrors.Errorf("failed to open the tmp file: %w", err)
			}
			return f, func() error {
				return os.RemoveAll(tempDirPath)
			}, nil
		} else {
			return io.NopCloser(bytes.NewReader(b)),
				func() error {
					b = []byte{}
					return nil
				},
				nil
		}
	}
}
