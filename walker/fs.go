package walker

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	swalker "github.com/saracen/walker"
	"golang.org/x/xerrors"
)

type Dir struct {
	walker
}

func NewDir(skipFiles, skipDirs []string) Dir {
	return Dir{
		walker: newWalker(skipFiles, skipDirs),
	}
}

// Walk walks the file tree rooted at root, calling WalkFunc for each file or
// directory in the tree, including root, but a directory to be ignored will be skipped.
func (w Dir) Walk(root string, fn WalkFunc) error {
	// walk function called for every path found
	walkFn := func(pathname string, fi os.FileInfo) error {
		pathname = filepath.Clean(pathname)

		if fi.IsDir() {
			if w.shouldSkipDir(pathname) {
				return filepath.SkipDir
			}
			return nil
		} else if !fi.Mode().IsRegular() {
			return nil
		} else if w.shouldSkipFile(pathname) {
			return nil
		}

		if err := fn(pathname, fi, w.fileOpener(fi, pathname)); err != nil {
			return xerrors.Errorf("failed to analyze file: %w", err)
		}
		return nil
	}

	// error function called for every error encountered
	errorCallbackOption := swalker.WithErrorCallback(func(pathname string, err error) error {
		// ignore permission errors
		if os.IsPermission(err) {
			return nil
		}
		// halt traversal on any other error
		return xerrors.Errorf("unknown error with %s: %w", pathname, err)
	})

	// Multiple goroutines stat the filesystem concurrently. The provided
	// walkFn must be safe for concurrent use.
	if err := swalker.Walk(root, walkFn, errorCallbackOption); err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}
	return nil
}

// fileOpener opens a file.
// If the file size is greater than or equal to N, it executes os.Open on each call without caching the file data.
// If the file size is less than N, it opens the file once and the content is shared so that some analyzers can use the same data
func (w *walker) fileOpener(fi os.FileInfo, pathname string) func() (io.ReadCloser, func() error, error) {
	var once sync.Once
	var b []byte
	var err error

	return func() (io.ReadCloser, func() error, error) {
		if fi.Size() >= N {
			f, err := os.Open(pathname)
			if err != nil {
				return nil, nil, xerrors.Errorf("unable to open the file: %w", err)
			}
			return f, func() error { return nil }, nil
		}
		once.Do(func() {
			b, err = ioutil.ReadFile(pathname)
		})
		if err != nil {
			return nil, nil, xerrors.Errorf("unable to read the file: %w", err)
		}
		return io.NopCloser(bytes.NewReader(b)),
			func() error {
				b = []byte{}
				return nil
			}, nil
	}
}
