package rpm

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&rpmPkgAnalyzer{})
}

var requiredFiles = []string{
	"usr/lib/sysimage/rpm/Packages",
	"var/lib/rpm/Packages",
}

type rpmPkgAnalyzer struct{}

func (a rpmPkgAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	parsedPkgs, err := a.parsePkgInfo(target.Content)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse rpmdb: %w", err)
	}

	return &analyzer.AnalysisResult{
		PackageInfos: []types.PackageInfo{
			{
				FilePath: target.FilePath,
				Packages: parsedPkgs,
			},
		},
	}, nil
}

func (a rpmPkgAnalyzer) parsePkgInfo(packageBytes []byte) (pkgs []types.Package, err error) {
	tmpDir, err := ioutil.TempDir("", "rpm")
	defer os.RemoveAll(tmpDir)
	if err != nil {
		return nil, xerrors.Errorf("failed to create a temp dir: %w", err)
	}

	filename := filepath.Join(tmpDir, "Packages")
	err = ioutil.WriteFile(filename, packageBytes, 0700)
	if err != nil {
		return nil, xerrors.Errorf("failed to write a package file: %w", err)
	}

	// rpm-python 4.11.3 rpm-4.11.3-35.el7.src.rpm
	// Extract binary package names because RHSA refers to binary package names.
	db, err := rpmdb.Open(filename)
	if err != nil {
		return nil, xerrors.Errorf("failed to open RPM DB: %w", err)
	}

	// equivalent:
	//   new version: rpm -qa --qf "%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{SOURCERPM} %{ARCH}\n"
	//   old version: rpm -qa --qf "%{NAME} %{EPOCH} %{VERSION} %{RELEASE} %{SOURCERPM} %{ARCH}\n"
	pkgList, err := db.ListPackages()
	if err != nil {
		return nil, xerrors.Errorf("failed to list packages", err)
	}

	for _, pkg := range pkgList {
		arch := pkg.Arch
		if arch == "" {
			arch = "None"
		}

		// parse source rpm
		var srcName, srcVer, srcRel string
		if pkg.SourceRpm != "(none)" && pkg.SourceRpm != "" {
			// source epoch is not included in SOURCERPM
			srcName, srcVer, srcRel = splitFileName(pkg.SourceRpm)
		}

		p := types.Package{
			Name:            pkg.Name,
			Epoch:           pkg.Epoch,
			Version:         pkg.Version,
			Release:         pkg.Release,
			Arch:            arch,
			SrcName:         srcName,
			SrcEpoch:        pkg.Epoch, // NOTE: use epoch of binary package as epoch of src package
			SrcVersion:      srcVer,
			SrcRelease:      srcRel,
			Modularitylabel: pkg.Modularitylabel,
		}
		pkgs = append(pkgs, p)
	}

	return pkgs, nil
}

// splitFileName returns a name, version, release, epoch, arch
// e.g.
//    foo-1.0-1.i386.rpm returns foo, 1.0, 1, i386
//    1:bar-9-123a.ia64.rpm returns bar, 9, 123a, 1, ia64
// https://github.com/rpm-software-management/yum/blob/043e869b08126c1b24e392f809c9f6871344c60d/rpmUtils/miscutils.py#L301
func splitFileName(filename string) (name, ver, rel string) {
	if strings.HasSuffix(filename, ".rpm") {
		filename = filename[:len(filename)-4]
	}

	archIndex := strings.LastIndex(filename, ".")

	relIndex := strings.LastIndex(filename[:archIndex], "-")
	rel = filename[relIndex+1 : archIndex]

	verIndex := strings.LastIndex(filename[:relIndex], "-")
	ver = filename[verIndex+1 : relIndex]

	name = filename[:verIndex]
	return name, ver, rel
}

func (a rpmPkgAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a rpmPkgAnalyzer) Type() analyzer.Type {
	return analyzer.TypeRpm
}
