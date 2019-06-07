package os

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/knqyf263/fanal/extractor"
	"golang.org/x/xerrors"
)

// GetFileMap is test function
func GetFileMap(prefixPath string) (extractor.FileMap, error) {
	fileMap := extractor.FileMap{}
	err := filepath.Walk(
		prefixPath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			read, err := os.Open(path)
			if err != nil {
				return xerrors.Errorf("can't open file %s", path)
			}
			fileBytes, err := ioutil.ReadAll(read)
			if err != nil {
				return xerrors.Errorf("can't read file %s", path)
			}
			// delete prefix (directory) name. only leave etc/xxxx
			fileMap[path[(len(prefixPath)-1):]] = extractor.FileData{Body: fileBytes, FileMode: info.Mode()}
			return nil
		},
	)
	return fileMap, err
}
