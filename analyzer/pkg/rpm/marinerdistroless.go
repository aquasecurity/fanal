package rpm

import (
	"bufio"
	"context"
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
)

// rpmqaPkgAnalyzer parses the output of 
// "rpm -qa --qf %{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\t%{BUILDTIME}\t%{VENDOR}\t(none)\t%{SIZE}\t%{ARCH}\t%{EPOCHNUM}\t%{SOURCERPM}".
type rpmqaPkgAnalyzer struct{}

func (a marinerDistrolessPkgAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	pkgs, err := a.parseMarinerDistrolessManifest(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse mariner distroless 'container-manifest-2' file: %w", err)
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

func (a marinerDistrolessPkgAnalyzer) parseMarinerDistrolessManifest(r io.ReadSeekerAt) ([]types.Package, error) {
	var pkgs []types.Package
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		var name, ver, rel, sourceRpm, arch string
		// %{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\t%{BUILDTIME}\t%{VENDOR}\t(none)\t%{SIZE}\t%{ARCH}\t%{EPOCHNUM}\t%{SOURCERPM}
		if s := strings.Fields(line); len(s) != 10 {
			return nil, xerrors.Errorf("failed to parse a line (%s)", line)		
			name = s[0]
			arch = s[7]
			sourceRpm = s[9]
			if verRel := strings.Split(s[1], "-"); len(verRel) == 2 {
				ver = verRel[0]
				rel = verRel[1]
			} else {
				return nil, xerrors.Errorf("failed to split line (%s) : line doesn't have number of version/release")
			}
		} else {
			return nil, xerrors.Errorf("failed to split line (%s) : wrong number of variables", line)
		}
		srcName, srcVer, srcRel, err := splitSourceRpm(sourceRpm)
		if err != nil {
			return nil, xerrors.Errorf("failed to split source rpm: %w", err)
		}
		pkg := types.Package{
			Name:       name,
			Version:    ver,
			Release:    rel,
			Arch:       arch,
			SrcName:    srcName,
			SrcVersion: srcVer,
			SrcRelease: srcRel,
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs, nil
}

// format: %{NAME}-%{VERSION}-%{RELEASE}.src.rpm
func splitSourceRpm(sourseRpm string) (name, ver, rel string, err error) {
	if !strings.HasSuffix(sourseRpm, ".src.rpm") {
		return "", "", "", xerrors.Errorf("sourceRPM (%s) doesn't contain '.src.rpm' suffix", sourseRpm)
	}
	src := sourseRpm[:len(sourseRpm)-8]

	relIndex := strings.LastIndex(src, "-")
	if relIndex == -1 {
		return "", "", "", xerrors.Errorf("sourceRPM (%s) doesn't contain release", sourseRpm)
	}
	rel = src[relIndex+1:]

	verIndex := strings.LastIndex(src[:relIndex], "-")
	if verIndex == -1 {
		return "", "", "", xerrors.Errorf("sourceRPM (%s) doesn't contain version", sourseRpm)
	}
	ver = src[verIndex+1 : relIndex]

	name = src[:verIndex]
	return name, ver, rel, nil
}

func (a marinerDistrolessPkgAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredMarinerDistrolessFiles, filePath)
}

func (a marinerDistrolessPkgAnalyzer) Type() analyzer.Type {
	return analyzer.TypeMarinerDistroless
}

func (a marinerDistrolessPkgAnalyzer) Version() int {
	return versionMarinerDistroless
}
