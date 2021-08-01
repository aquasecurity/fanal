package dpkgpkglicenses

import (
	"bufio"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/aquasecurity/fanal/types"
	"github.com/kylelemons/godebug/pretty"
)

func TestParseDpkgPkgLicenseInfo(t *testing.T) {
	var tests = map[string]struct {
		path string
		pkg  types.Package
	}{
		"multiple_license_found_1": {
			path: "./testdata/usr/share/doc/liblzma5/copyright",
			pkg: types.Package{
				Name: "liblzma5", License: "Autoconf,GPL-2,GPL-2+,GPL-3,LGPL-2,LGPL-2.1,LGPL-2.1+,PD,PD-debian,config-h,noderivs,none,permissive-fsf,permissive-nowarranty,probably-PD,public domain",
			},
		},
		"multiple_license_found_2": {
			path: "./testdata/usr/share/doc/libnettle6/copyright",
			pkg: types.Package{
				Name: "libnettle6", License: "GAP,GPL,GPL-2,GPL-2+,LGPL,LGPL-2,LGPL-2+,LGPL-2.1+,other,public domain,public-domain",
			},
		},
		"multiple_license_found_3": {
			path: "./testdata/usr/share/doc/e2fsprogs/copyright",
			pkg: types.Package{
				Name: "e2fsprogs", License: "BSD-style license,GPL-2,LGPL-2",
			},
		},
	}
	a := debianPkgLicenseAnalyzer{}
	for testname, v := range tests {
		read, err := os.Open(v.path)
		if err != nil {
			t.Errorf("%s : can't open file %s", testname, v.path)
		}
		scanner := bufio.NewScanner(read)
		pkg := a.parseDpkgPkgLicenseInfo(scanner, v.path)
		pkg.License = sortLicenses(pkg.License)
		if err != nil {
			t.Errorf("%s : catch the error : %v", testname, err)
		}
		if !reflect.DeepEqual(v.pkg, pkg) {
			t.Errorf("[%s]\n diff: %s", testname, pretty.Compare(v.pkg, pkg))
		}
	}
}

func sortLicenses(licenseStr string) string {
	licenses := strings.Split(licenseStr, ",")
	if len(licenses) > 0 {
		sort.Strings(licenses)
		return strings.Join(licenses, ",")
	}
	return licenseStr

}
