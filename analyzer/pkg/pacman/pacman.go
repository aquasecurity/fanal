package pacman

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&pacmanAnalyzer{})
}

const version = 1

const installDir = "var/lib/pacman/local/"

type pacmanAnalyzer struct{}

func (a pacmanAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(target.Content))
	dir, fileName := filepath.Split(target.FilePath)
	if !strings.HasPrefix(dir, installDir) {
		return nil, nil
	}
	if fileName == "desc" {
		pkg, err := a.parsePacmanPkgDesc(scanner)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse desc: %w", err)
		}
		return &analyzer.AnalysisResult{
			PackageInfos: []types.PackageInfo{
				{FilePath: target.FilePath, Packages: []types.Package{pkg}},
			},
		}, nil
	}
	if fileName == "files" {
		result, err := a.parsePacmanPkgFiles(scanner)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse files: %w", err)
		}
		return result, nil
	}
	return nil, nil
}

func (a pacmanAnalyzer) parsePacmanPkgDesc(scanner *bufio.Scanner) (types.Package, error) {
	var pkg types.Package
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "%NAME%") {
			if scanner.Scan() {
				pkg.Name = scanner.Text()
			}
		} else if strings.HasPrefix(line, "%VERSION%") {
			if scanner.Scan() {
				version := scanner.Text()
				pkg.Version = version
				pkg.SrcVersion = version
			}
		} else if strings.HasPrefix(line, "%BASE%") {
			if scanner.Scan() {
				pkg.SrcName = scanner.Text()
			}
		} else if strings.HasPrefix(line, "%ARCH%") {
			if scanner.Scan() {
				pkg.Arch = scanner.Text()
			}
		} else if strings.HasPrefix(line, "%LICENSE%") {
			if scanner.Scan() {
				pkg.License = scanner.Text()
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return types.Package{}, xerrors.Errorf("scan error: %w", err)
	}

	return pkg, nil
}

// parsePacmanPkgFiles parses /var/lib/pacman/local/*/files
func (a pacmanAnalyzer) parsePacmanPkgFiles(scanner *bufio.Scanner) (*analyzer.AnalysisResult, error) {
	var installedFiles []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "%FILES%") {
			continue
		}
		if strings.HasPrefix(line, "%BACKUP%") {
			break
		}

		if _, fileName := filepath.Split(line); fileName != "" {
			installedFiles = append(installedFiles, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, xerrors.Errorf("scan error: %w", err)
	}

	return &analyzer.AnalysisResult{
		SystemInstalledFiles: installedFiles,
	}, nil
}

func (a pacmanAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	dir, fileName := filepath.Split(filePath)
	if !strings.HasPrefix(dir, installDir) {
		return false
	}
	return fileName == "desc" || fileName == "files"
}

func (a pacmanAnalyzer) Type() analyzer.Type {
	return analyzer.TypePacman
}

func (a pacmanAnalyzer) Version() int {
	return version
}
