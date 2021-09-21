package walker

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/log"
	"github.com/aquasecurity/fanal/utils"
)

var (
	skipDirs   = []string{".git", "vendor"}
	systemDirs = []string{"proc", "sys"}
)

type WalkFunc func(filePath string, info os.FileInfo, opener analyzer.Opener) error

type walker struct {
	skipFiles []string
	skipDirs  []string
}

func newWalker(skipFiles, skipDirs []string) walker {
	var cleanSkipFiles, cleanSkipDirs []string
	for _, skipFile := range skipFiles {
		skipFile = strings.TrimLeft(filepath.Clean(skipFile), utils.PathSeparator)
		cleanSkipFiles = append(cleanSkipFiles, skipFile)
	}

	for _, skipDir := range skipDirs {
		skipDir = strings.TrimLeft(filepath.Clean(skipDir), utils.PathSeparator)
		cleanSkipDirs = append(cleanSkipDirs, skipDir)
	}

	return walker{
		skipFiles: cleanSkipFiles,
		skipDirs:  cleanSkipDirs,
	}
}

func (w walker) shouldSkip(filePath string) bool {
	filePath = strings.TrimLeft(filePath, "/")

	// skip files
	if utils.StringInSlice(filePath, w.skipFiles) {
		return true
	}

	// skip application dirs
	for _, path := range strings.Split(filePath, utils.PathSeparator) {
		if utils.StringInSlice(path, skipDirs) {
			return true
		}
	}

	// skip system dirs and specified dirs
	for _, skipDir := range append(w.skipDirs, systemDirs...) {
		rel, err := filepath.Rel(skipDir, filePath)
		if err != nil {
			log.Logger.Warnf("Unexpected error while skipping directories: %s", err)
			return false
		}
		if !strings.HasPrefix(rel, "..") {
			return true
		}
	}

	return false
}

// fileOnceOpener opens a file once and the content is shared so that some analyzers can use the same data
func (w walker) fileOnceOpener(r io.Reader) func() ([]byte, error) {
	var once sync.Once
	var b []byte
	var err error

	return func() ([]byte, error) {
		once.Do(func() {
			b, err = io.ReadAll(r)
		})
		if err != nil {
			return nil, xerrors.Errorf("unable to read tar file: %w", err)
		}
		return b, nil
	}
}
