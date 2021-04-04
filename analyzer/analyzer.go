package analyzer

import (
	"os"
	"sort"
	"strings"
	"sync"

	"golang.org/x/xerrors"

	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/log"
	"github.com/aquasecurity/fanal/types"
)

var (
	analyzers       []analyzer
	configAnalyzers []configAnalyzer

	// ErrUnknownOS occurs when unknown OS is analyzed.
	ErrUnknownOS = xerrors.New("unknown OS")
	// ErrPkgAnalysis occurs when the analysis of packages is failed.
	ErrPkgAnalysis = xerrors.New("failed to analyze packages")
	// ErrNoPkgsDetected occurs when the required files for an OS package manager are not detected
	ErrNoPkgsDetected = xerrors.New("no packages detected")
)

type AnalysisTarget struct {
	FilePath string
	Content  []byte
}

type analyzer interface {
	Type() Type
	Version() int
	Analyze(input AnalysisTarget) (*AnalysisResult, error)
	Required(filePath string, info os.FileInfo) bool
}

type configAnalyzer interface {
	Type() Type
	Version() int
	Analyze(targetOS types.OS, content []byte) ([]types.Package, error)
	Required(osFound types.OS) bool
}

func RegisterAnalyzer(analyzer analyzer) {
	analyzers = append(analyzers, analyzer)
}

func RegisterConfigAnalyzer(analyzer configAnalyzer) {
	configAnalyzers = append(configAnalyzers, analyzer)
}

type Opener func() ([]byte, error)

type AnalysisResult struct {
	m                 sync.Mutex
	OS                *types.OS
	PackageInfos      []types.PackageInfo
	Applications      []types.Application
	Misconfigurations []types.Misconfiguration
}

func (r *AnalysisResult) isEmpty() bool {
	return r.OS == nil && len(r.PackageInfos) == 0 && len(r.Applications) == 0 && len(r.Misconfigurations) == 0
}

func (r *AnalysisResult) Sort() {
	sort.Slice(r.PackageInfos, func(i, j int) bool {
		return r.PackageInfos[i].FilePath < r.PackageInfos[j].FilePath
	})

	for _, pi := range r.PackageInfos {
		sort.Slice(pi.Packages, func(i, j int) bool {
			return pi.Packages[i].Name < pi.Packages[j].Name
		})
	}

	sort.Slice(r.Applications, func(i, j int) bool {
		return r.Applications[i].FilePath < r.Applications[j].FilePath
	})

	for _, app := range r.Applications {
		sort.Slice(app.Libraries, func(i, j int) bool {
			if app.Libraries[i].Library.Name != app.Libraries[j].Library.Name {
				return app.Libraries[i].Library.Name < app.Libraries[j].Library.Name
			}
			return app.Libraries[i].Library.Version < app.Libraries[j].Library.Version
		})
	}

	sort.Slice(r.Misconfigurations, func(i, j int) bool {
		return r.Misconfigurations[i].FilePath < r.Misconfigurations[j].FilePath
	})

	for _, misconf := range r.Misconfigurations {
		sort.Sort(misconf.Successes)
		sort.Sort(misconf.Failures)
		sort.Sort(misconf.Warnings)
		sort.Sort(misconf.Exceptions)
	}
}

func (r *AnalysisResult) Merge(new *AnalysisResult) {
	if new == nil || new.isEmpty() {
		return
	}

	// this struct is accessed by multiple goroutines
	r.m.Lock()
	defer r.m.Unlock()

	if new.OS != nil {
		// OLE also has /etc/redhat-release and it detects OLE as RHEL by mistake.
		// In that case, OS must be overwritten with the content of /etc/oracle-release.
		// There is the same problem between Debian and Ubuntu.
		if r.OS == nil || r.OS.Family == aos.RedHat || r.OS.Family == aos.Debian {
			r.OS = new.OS
		}
	}

	if len(new.PackageInfos) > 0 {
		r.PackageInfos = append(r.PackageInfos, new.PackageInfos...)
	}

	if len(new.Applications) > 0 {
		r.Applications = append(r.Applications, new.Applications...)
	}

	for _, m := range new.Misconfigurations {
		if len(m.Successes) > 0 || len(m.Failures) > 0 || len(m.Warnings) > 0 || len(m.Exceptions) > 0 {
			r.Misconfigurations = append(r.Misconfigurations, m)
		}
	}
}

type Analyzer struct {
	drivers           []analyzer
	configDrivers     []configAnalyzer
	disabledAnalyzers []Type
}

func NewAnalyzer(disabledAnalyzers []Type) Analyzer {
	var drivers []analyzer
	for _, a := range analyzers {
		if isDisabled(a.Type(), disabledAnalyzers) {
			continue
		}
		drivers = append(drivers, a)
	}

	var configDrivers []configAnalyzer
	for _, a := range configAnalyzers {
		if isDisabled(a.Type(), disabledAnalyzers) {
			continue
		}
		configDrivers = append(configDrivers, a)
	}

	return Analyzer{
		drivers:           drivers,
		configDrivers:     configDrivers,
		disabledAnalyzers: disabledAnalyzers,
	}
}

// AnalyzerVersions returns analyzer version identifier used for cache keys.
func (a Analyzer) AnalyzerVersions() map[string]int {
	versions := map[string]int{}
	for _, aa := range analyzers {
		if isDisabled(aa.Type(), a.disabledAnalyzers) {
			versions[string(aa.Type())] = 0
			continue
		}
		versions[string(aa.Type())] = aa.Version()
	}
	return versions
}

// ImageConfigAnalyzerVersions returns analyzer version identifier used for cache keys.
func (a Analyzer) ImageConfigAnalyzerVersions() map[string]int {
	versions := map[string]int{}
	for _, ca := range configAnalyzers {
		if isDisabled(ca.Type(), a.disabledAnalyzers) {
			versions[string(ca.Type())] = 0
			continue
		}
		versions[string(ca.Type())] = ca.Version()
	}
	return versions
}

func (a Analyzer) AnalyzeFile(wg *sync.WaitGroup, result *AnalysisResult, filePath string, info os.FileInfo,
	opener Opener) error {
	if info.IsDir() {
		return nil
	}

	for _, d := range a.drivers {
		// filepath extracted from tar file doesn't have the prefix "/"
		if !d.Required(strings.TrimLeft(filePath, "/"), info) {
			continue
		}
		b, err := opener()
		if err != nil {
			return xerrors.Errorf("unable to open a file (%s): %w", filePath, err)
		}

		wg.Add(1)
		go func(a analyzer, target AnalysisTarget) {
			defer wg.Done()

			ret, err := a.Analyze(target)
			if err != nil && !xerrors.Is(err, aos.AnalyzeOSError) {
				log.Logger.Debugf("Analysis error: %s", err)
				return
			}
			result.Merge(ret)
		}(d, AnalysisTarget{FilePath: filePath, Content: b})
	}
	return nil
}

func (a Analyzer) AnalyzeImageConfig(targetOS types.OS, configBlob []byte) []types.Package {
	for _, d := range a.configDrivers {
		if !d.Required(targetOS) {
			continue
		}

		pkgs, err := d.Analyze(targetOS, configBlob)
		if err != nil {
			continue
		}
		return pkgs
	}
	return nil
}

func isDisabled(t Type, disabled []Type) bool {
	for _, d := range disabled {
		if t == d {
			return true
		}
	}
	return false
}

func CheckPackage(pkg *types.Package) bool {
	return pkg.Name != "" && pkg.Version != ""
}
