package apk

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"golang.org/x/xerrors"

	"github.com/knqyf263/fanal/extractor/docker"

	"github.com/knqyf263/fanal/analyzer/os"
	"github.com/pkg/errors"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/extractor"
)

func init() {
	analyzer.RegisterCommandAnalyzer(&alpineCmdAnalyzer{})
}

type alpineCmdAnalyzer struct{}

type archive struct {
	Origin   string
	Versions version
}

type version map[string]int

const (
	apkIndexArchiveURL = "https://raw.githubusercontent.com/knqyf263/apkIndex-archive/master/alpine/v%s/main/x86_64/history.json"
)

var (
	apkIndexArchive map[string]archive
)

func (a alpineCmdAnalyzer) Analyze(targetOS analyzer.OS, fileMap extractor.FileMap) (pkgs []analyzer.Package, err error) {
	if targetOS.Family != os.Alpine {
		return nil, xerrors.New("not target")
	}

	if err := a.fetchApkIndexArchive(targetOS); err != nil {
		return nil, err
	}

	for _, filename := range a.RequiredFiles() {
		file, ok := fileMap[filename]
		if !ok {
			continue
		}
		var config docker.Config
		if err := json.Unmarshal(file, &config); err != nil {
			return nil, err
		}
		pkgs = append(pkgs, a.parseConfig(config)...)
	}
	if len(pkgs) == 0 {
		return pkgs, errors.New("No package detected")
	}
	return pkgs, nil
}
func (a alpineCmdAnalyzer) fetchApkIndexArchive(targetOS analyzer.OS) (err error) {
	if apkIndexArchive != nil {
		return nil
	}
	osVer := targetOS.Name
	if strings.Count(osVer, ".") > 1 {
		osVer = osVer[:strings.LastIndex(osVer, ".")]
	}

	url := fmt.Sprintf(apkIndexArchiveURL, osVer)
	resp, err := http.Get(url)
	if err != nil {
		return xerrors.Errorf("failed to fetch APKINDEX archive: %w", err)
	}
	defer resp.Body.Close()

	if err = json.NewDecoder(resp.Body).Decode(&apkIndexArchive); err != nil {
		return xerrors.Errorf("failed to decode APKINDEX JSON: %w", err)
	}

	return nil
}

func (a alpineCmdAnalyzer) parseConfig(config docker.Config) (packages []analyzer.Package) {
	envs := map[string]string{}
	for _, env := range config.ContainerConfig.Env {
		index := strings.Index(env, "=")
		envs["$"+env[:index]] = env[index+1:]
	}

	for _, history := range config.History {
		pkgs := a.parseCommand(history.CreatedBy, envs)
		pkgs = a.guessVersion(pkgs, history.Created)
		packages = append(packages, pkgs...)
	}

	return packages
}

func (a alpineCmdAnalyzer) parseCommand(command string, envs map[string]string) (pkgs []analyzer.Package) {
	if strings.Contains(command, "#(nop)") {
		return nil
	}

	command = strings.TrimPrefix(command, "/bin/sh -c")
	var commands []string
	for _, cmd := range strings.Split(command, "&&") {
		for _, c := range strings.Split(cmd, ";") {
			commands = append(commands, strings.TrimSpace(c))
		}
	}
	for _, cmd := range commands {
		if !strings.HasPrefix(cmd, "apk") {
			continue
		}

		var add bool
		for _, field := range strings.Fields(cmd) {
			if strings.HasPrefix(field, "-") || strings.HasPrefix(field, ".") {
				continue
			} else if field == "add" {
				add = true
			} else if add {
				if strings.HasPrefix(field, "$") {
					for _, pkg := range strings.Fields(envs[field]) {
						pkgs = append(pkgs, analyzer.Package{
							Name: pkg,
						})
					}
					continue
				}
				pkgs = append(pkgs, analyzer.Package{
					Name: field,
				})
			}
		}
	}
	return pkgs
}

type historyVersion struct {
	Version string
	BuiltAt int
}

func (a alpineCmdAnalyzer) guessVersion(originalPkgs []analyzer.Package, createdAt time.Time) (pkgs []analyzer.Package) {
	for _, pkg := range originalPkgs {
		archive, ok := apkIndexArchive[pkg.Name]
		if !ok {
			continue
		}

		var historyVersions []historyVersion
		for version, builtAt := range archive.Versions {
			historyVersions = append(historyVersions, historyVersion{
				Version: version,
				BuiltAt: builtAt,
			})
		}
		sort.Slice(historyVersions, func(i, j int) bool {
			return historyVersions[i].BuiltAt < historyVersions[j].BuiltAt
		})

		createdUnix := int(createdAt.Unix())
		var candidateVersion string
		for _, historyVersion := range historyVersions {
			if historyVersion.BuiltAt <= createdUnix {
				candidateVersion = historyVersion.Version
			} else if createdUnix < historyVersion.BuiltAt {
				break
			}
		}
		if candidateVersion == "" {
			continue
		}

		pkgs = append(pkgs, analyzer.Package{
			Name:    pkg.Name,
			Version: candidateVersion,
		})

		// Add origin package name
		if archive.Origin != "" && archive.Origin != pkg.Name {
			pkgs = append(pkgs, analyzer.Package{
				Name:    archive.Origin,
				Version: candidateVersion,
			})
		}
	}
	return pkgs
}

func (a alpineCmdAnalyzer) RequiredFiles() []string {
	return []string{"/config"} // special file
}
