package cache

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/aquasecurity/fanal/artifact"

	"golang.org/x/mod/sumdb/dirhash"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer/config"
)

func CalcKey(id string, analyzerVersions, hookVersions map[string]int, artifactOpt artifact.Option, scannerOpt config.ScannerOption) (string, error) {
	// Sort options for consistent results
	artifactOpt.Sort()
	scannerOpt.Sort()

	h := sha256.New()

	// Write id
	if _, err := h.Write([]byte(id)); err != nil {
		return "", xerrors.Errorf("sha256 error: %w", err)
	}

	// Write analyzer versions
	if err := json.NewEncoder(h).Encode(analyzerVersions); err != nil {
		return "", xerrors.Errorf("json encode error: %w", err)
	}

	// Write hook versions
	if err := json.NewEncoder(h).Encode(hookVersions); err != nil {
		return "", xerrors.Errorf("json encode error: %w", err)
	}

	// Write skipped files and dirs
	skipped := append(artifactOpt.SkipDirs, artifactOpt.SkipFiles...)
	if err := json.NewEncoder(h).Encode(skipped); err != nil {
		return "", xerrors.Errorf("json encode error: %w", err)
	}

	// Write policy and data contents
	for _, paths := range [][]string{scannerOpt.PolicyPaths, scannerOpt.DataPaths} {
		for _, p := range paths {
			s, err := dirhash.HashDir(p, "", dirhash.DefaultHash)
			if err != nil {
				return "", xerrors.Errorf("hash dir (%s): %w", p, err)
			}

			if _, err = h.Write([]byte(s)); err != nil {
				return "", xerrors.Errorf("sha256 write error: %w", err)
			}
		}
	}

	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}
