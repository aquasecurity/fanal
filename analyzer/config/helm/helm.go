package helm

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"strings"
)

func IsHelmChart(file io.Reader, path string) bool {

	var err error
	var fr = file

	if IsZip(path) {
		if fr, err = gzip.NewReader(file); err != nil {
			return false
		}
	}
	tr := tar.NewReader(fr)

	for {
		header, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return false
		}

		if header.Typeflag == tar.TypeReg && strings.HasSuffix(header.Name, "Chart.yaml") {
			return true
		}
	}
	return false
}

func IsArchive(path string) bool {
	if strings.HasSuffix(path, ".tar") ||
		strings.HasSuffix(path, ".tgz") ||
		strings.HasSuffix(path, ".tar.gz") {
		return true
	}
	return false
}

func IsZip(path string) bool {
	if strings.HasSuffix(path, ".tgz") ||
		strings.HasSuffix(path, ".tar.gz") {
		return true
	}
	return false
}
