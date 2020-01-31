package cache

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"
)

const (
	cacheDirName = "fanal"
)

var (
	replacer = strings.NewReplacer("/", "_")
)

type Cache interface {
	Get(key string) (reader io.ReadCloser)
	MissingKeys(keys []string) []string
	Set(key string, value interface{}) (err error)
	SetBytes(key string, value []byte) (err error)
	Clear() (err error)
}

type FSCache struct {
	directory string
}

func New(cacheDir string) Cache {
	return &FSCache{directory: filepath.Join(cacheDir, cacheDirName)}
}

func (fs FSCache) Get(key string) io.ReadCloser {
	filePath := filepath.Join(fs.directory, replacer.Replace(key))
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	return f
}

func (fs FSCache) MissingKeys(keys []string) []string {
	return keys
}

func (fs FSCache) Set(key string, value interface{}) error {
	//filePath := filepath.Join(fs.directory, replacer.Replace(key))
	//if err := os.MkdirAll(fs.directory, os.ModePerm); err != nil {
	//	return nil, xerrors.Errorf("failed to mkdir all: %w", err)
	//}
	//cacheFile, err := os.Create(filePath)
	//if err != nil {
	//	return r, xerrors.Errorf("failed to create cache file: %w", err)
	//}
	//
	//tee := io.TeeReader(r, cacheFile)
	return nil
}

func (fs FSCache) SetBytes(key string, b []byte) error {
	filePath := filepath.Join(fs.directory, replacer.Replace(key))
	if err := os.MkdirAll(fs.directory, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to mkdir all: %w", err)
	}
	cacheFile, err := os.Create(filePath)
	if err != nil {
		return xerrors.Errorf("failed to create cache file: %w", err)
	}

	if _, err := cacheFile.Write(b); err != nil {
		return xerrors.Errorf("cache write error: %w", err)
	}
	return nil
}

func (fs FSCache) Clear() error {
	if err := os.RemoveAll(fs.directory); err != nil {
		return xerrors.New("failed to remove cache")
	}
	return nil
}
