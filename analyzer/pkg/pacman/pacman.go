package pacman

import (
	"bufio"
	"context"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	pacmanVersion "github.com/MaineK00n/go-pacman-version"

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

func (a pacmanAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	dir, fileName := filepath.Split(input.FilePath)
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
				{FilePath: input.FilePath, Packages: []types.Package{pkg}},
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
				if !pacmanVersion.Valid(version) {
					log.Printf("Invalid Version Found : OS %s, Package %s, Version %s", "arch", pkg.Name, version)
					continue
				}
				splitted := strings.SplitN(version, ":", 2)
				if len(splitted) == 1 {
					pkg.Epoch = 0
					version = splitted[0]
				} else {
					var err error
					pkg.Epoch, err = strconv.Atoi(splitted[0])
					if err != nil {
						return types.Package{}, xerrors.Errorf("failed to convert epoch: %w", err)
					}

					if pkg.Epoch < 0 {
						return types.Package{}, xerrors.Errorf("epoch is negative")
					}
					version = splitted[1]
				}

				index := strings.Index(version, "-")
				if index >= 0 {
					ver := version[:index]
					rel := version[index+1:]
					pkg.Version = ver
					pkg.Release = rel
					pkg.SrcVersion = ver
					pkg.SrcRelease = rel
				} else {
					pkg.Version = version
					pkg.SrcVersion = version
				}
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
