package walker

import (
	"os"
	"path/filepath"

	swalker "github.com/saracen/walker"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
)

type FS struct {
	walker
}

func NewFS(skipFiles, skipDirs []string) FS {
	return FS{
		walker: newWalker(skipFiles, skipDirs),
	}
}

// Walk walks the file tree rooted at root, calling WalkFunc for each file or
// directory in the tree, including root, but a directory to be ignored will be skipped.
func (w FS) Walk(root string, fn WalkFunc) error {
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

		if err := fn(pathname, fi, w.fileOpener(pathname)); err != nil {
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

// fileOpener returns a function opening a file.
func (w *walker) fileOpener(pathname string) func() (dio.ReadSeekCloserAt, error) {
	return func() (dio.ReadSeekCloserAt, error) {
		return os.Open(pathname)
	}
}
