package testutils

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

func openImage(filePath string) (io.Reader, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	var r io.Reader
	if strings.HasSuffix(filePath, ".gz") {
		r, err = gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
	} else {
		r = f
	}

	return r, nil
}

func extractManifest(r io.Reader) ([]byte, error) {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Name != "manifest.json" {
			continue
		}
		return ioutil.ReadAll(r)
	}
	return nil, errors.New("no manifest")
}
