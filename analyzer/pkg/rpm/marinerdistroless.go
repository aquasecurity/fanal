package rpm

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/io"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&marinerDistrolessPkgAnalyzer{})
}

const versionMarinerDistroless = 1

var (
	requiredMarinerDistrolessFiles = []string{"var/lib/rpmmanifest/container-manifest-2"}

	//errUnexpectedNameFormat = xerrors.New("unexpected name format")
)

type marinerDistrolessPkgAnalyzer struct{}

func (a marinerDistrolessPkgAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	pkgs, err := a.parseMarinerDistrolessManifest(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse mariner distroless 'container-manifest-2': %w", err)
	}
	return &analyzer.AnalysisResult{
		PackageInfos: []types.PackageInfo{
			{
				FilePath: input.FilePath,
				Packages: pkgs,
			},
		},
	}, nil
}

func (m marinerDistrolessPkgAnalyzer) parseMarinerDistrolessManifest(r io.ReadSeekerAt) ([]types.Package, error) {
	var pkgs []types.Package
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		var sourceRpm, arch string
		// %{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\t%{BUILDTIME}\t%{VENDOR}\t(none)\t%{SIZE}\t%{ARCH}\t%{EPOCHNUM}\t%{SOURCERPM}\n
		if s := strings.Split(line, "\t"); len(s) == 10 {
			arch = s[7]
			sourceRpm = s[9]
		} else {
			return nil, xerrors.Errorf("failed to split source rpm: wrong number of variables")
		}
		name, ver, rel, err := splitSourceRpm(sourceRpm)
		if err != nil {
			return nil, xerrors.Errorf("failed to split source rpm: %w", err)
		}
		pkg := types.Package{
			Name:    name,
			Version: ver,
			Release: rel,
			Arch:    arch,
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs, nil
}

func splitSourceRpm(filename string) (name, ver, rel string, err error) {
	if !strings.HasSuffix(filename, ".src.rpm") {
		return "", "", "", xerrors.Errorf("sourceRPM doesn't contain '.src.rpm' suffix: %q", filename)
	}
	filename = filename[:len(filename)-8]

	relIndex := strings.LastIndex(filename, "-")
	if relIndex == -1 {
		return "", "", "", xerrors.Errorf("sourceRPM doesn't contain release: %q", filename)
	}
	rel = filename[relIndex+1:]

	verIndex := strings.LastIndex(filename[:relIndex], "-")
	if verIndex == -1 {
		return "", "", "", xerrors.Errorf("sourceRPM doesn't contain version: %q", filename)
	}
	ver = filename[verIndex+1 : relIndex]

	name = filename[:verIndex]
	return name, ver, rel, nil
}

func (a marinerDistrolessPkgAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	if strings.Contains(filePath, "container-manifest") {
		fmt.Println(filePath)
	}
	return utils.StringInSlice(filePath, requiredMarinerDistrolessFiles)
}

func (a marinerDistrolessPkgAnalyzer) Type() analyzer.Type {
	return analyzer.TypeMarinerDistroless
}

func (a marinerDistrolessPkgAnalyzer) Version() int {
	return versionMarinerDistroless
}

//func packageProvidedByVendor(pkgVendor string) bool {
//	for _, vendor := range osVendors {
//		if strings.HasPrefix(pkgVendor, vendor) {
//			return true
//		}
//	}
//	return false
//}
