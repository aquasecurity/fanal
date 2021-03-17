package cache

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/mod/sumdb/dirhash"

	"github.com/aquasecurity/fanal/analyzer/config"
)

func CalcKey(id, version string, opt *config.ScannerOption) (string, error) {
	// Sort options for consistent results
	opt.Sort()

	h := sha256.New()

	for _, s := range append([]string{id, version}, opt.FilePatterns...) {
		_, err := h.Write([]byte(s))
		if err != nil {
			return "", err
		}
	}

	for _, paths := range [][]string{opt.PolicyPaths, opt.DataPaths} {
		for _, p := range paths {
			s, err := dirhash.HashDir(p, "", dirhash.DefaultHash)
			if err != nil {
				return "", err
			}

			if _, err = h.Write([]byte(s)); err != nil {
				return "", err
			}
		}
	}

	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}
