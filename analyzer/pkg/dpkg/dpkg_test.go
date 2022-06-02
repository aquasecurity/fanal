package dpkg

import (
	"context"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

func Test_dpkgAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name     string
		testFile string
		filePath string
		want     *analyzer.AnalysisResult
		wantErr  bool
	}{
		{
			name:     "valid",
			testFile: "./testdata/dpkg",
			filePath: "var/lib/dpkg/status",
			want: &analyzer.AnalysisResult{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/dpkg/status",
						Packages: []types.Package{
							{Name: "adduser", Version: "3.116ubuntu1", SrcName: "adduser", SrcVersion: "3.116ubuntu1"},
							{Name: "apt", Version: "1.6.3ubuntu0.1", SrcName: "apt", SrcVersion: "1.6.3ubuntu0.1"},
							{
								Name: "base-files", Version: "10.1ubuntu2.2", SrcName: "base-files",
								SrcVersion: "10.1ubuntu2.2",
							},
							{Name: "base-passwd", Version: "3.5.44", SrcName: "base-passwd", SrcVersion: "3.5.44"},
							{Name: "bash", Version: "4.4.18-2ubuntu1", SrcName: "bash", SrcVersion: "4.4.18-2ubuntu1"},
							{
								Name: "bsdutils", Version: "1:2.31.1-0.4ubuntu3.1", SrcName: "util-linux",
								SrcVersion: "2.31.1-0.4ubuntu3.1",
							},
							{Name: "bzip2", Version: "1.0.6-8.1", SrcName: "bzip2", SrcVersion: "1.0.6-8.1"},
							{
								Name: "coreutils", Version: "8.28-1ubuntu1", SrcName: "coreutils",
								SrcVersion: "8.28-1ubuntu1",
							},
							{Name: "dash", Version: "0.5.8-2.10", SrcName: "dash", SrcVersion: "0.5.8-2.10"},
							{Name: "debconf", Version: "1.5.66", SrcName: "debconf", SrcVersion: "1.5.66"},
							{Name: "debianutils", Version: "4.8.4", SrcName: "debianutils", SrcVersion: "4.8.4"},
							{Name: "diffutils", Version: "1:3.6-1", SrcName: "diffutils", SrcVersion: "1:3.6-1"},
							{Name: "dpkg", Version: "1.19.0.5ubuntu2", SrcName: "dpkg", SrcVersion: "1.19.0.5ubuntu2"},
							{Name: "e2fsprogs", Version: "1.44.1-1", SrcName: "e2fsprogs", SrcVersion: "1.44.1-1"},
							{
								Name: "fdisk", Version: "2.31.1-0.4ubuntu3.1", SrcName: "util-linux",
								SrcVersion: "2.31.1-0.4ubuntu3.1",
							},
							{
								Name: "findutils", Version: "4.6.0+git+20170828-2", SrcName: "findutils",
								SrcVersion: "4.6.0+git+20170828-2",
							},
							{
								Name: "gcc-8-base", Version: "8-20180414-1ubuntu2", SrcName: "gcc-8",
								SrcVersion: "8-20180414-1ubuntu2",
							},
							{
								Name: "gpgv", Version: "2.2.4-1ubuntu1.1", SrcName: "gnupg2",
								SrcVersion: "2.2.4-1ubuntu1.1",
							},
							{Name: "grep", Version: "3.1-2", SrcName: "grep", SrcVersion: "3.1-2"},
							{Name: "gzip", Version: "1.6-5ubuntu1", SrcName: "gzip", SrcVersion: "1.6-5ubuntu1"},
							{Name: "hostname", Version: "3.20", SrcName: "hostname", SrcVersion: "3.20"},
							{
								Name: "init-system-helpers", Version: "1.51", SrcName: "init-system-helpers",
								SrcVersion: "1.51",
							},
							{Name: "libacl1", Version: "2.2.52-3build1", SrcName: "acl", SrcVersion: "2.2.52-3build1"},
							{
								Name: "libapt-pkg5.0", Version: "1.6.3ubuntu0.1", SrcName: "apt",
								SrcVersion: "1.6.3ubuntu0.1",
							},
							{
								Name: "libattr1", Version: "1:2.4.47-2build1", SrcName: "attr",
								SrcVersion: "1:2.4.47-2build1",
							},
							{
								Name: "libaudit-common", Version: "1:2.8.2-1ubuntu1", SrcName: "audit",
								SrcVersion: "1:2.8.2-1ubuntu1",
							},
							{
								Name: "libaudit1", Version: "1:2.8.2-1ubuntu1", SrcName: "audit",
								SrcVersion: "1:2.8.2-1ubuntu1",
							},
							{
								Name: "libblkid1", Version: "2.31.1-0.4ubuntu3.1", SrcName: "util-linux",
								SrcVersion: "2.31.1-0.4ubuntu3.1",
							},
							{Name: "libbz2-1.0", Version: "1.0.6-8.1", SrcName: "bzip2", SrcVersion: "1.0.6-8.1"},
							{Name: "libc-bin", Version: "2.27-3ubuntu1", SrcName: "glibc", SrcVersion: "2.27-3ubuntu1"},
							{Name: "libc6", Version: "2.27-3ubuntu1", SrcName: "glibc", SrcVersion: "2.27-3ubuntu1"},
							{Name: "libcap-ng0", Version: "0.7.7-3.1", SrcName: "libcap-ng", SrcVersion: "0.7.7-3.1"},
							{Name: "libcom-err2", Version: "1.44.1-1", SrcName: "e2fsprogs", SrcVersion: "1.44.1-1"},
							{
								Name: "libdb5.3", Version: "5.3.28-13.1ubuntu1", SrcName: "db5.3",
								SrcVersion: "5.3.28-13.1ubuntu1",
							},
							{
								Name: "libdebconfclient0", Version: "0.213ubuntu1", SrcName: "cdebconf",
								SrcVersion: "0.213ubuntu1",
							},
							{Name: "libext2fs2", Version: "1.44.1-1", SrcName: "e2fsprogs", SrcVersion: "1.44.1-1"},
							{
								Name: "libfdisk1", Version: "2.31.1-0.4ubuntu3.1", SrcName: "util-linux",
								SrcVersion: "2.31.1-0.4ubuntu3.1",
							},
							{Name: "libffi6", Version: "3.2.1-8", SrcName: "libffi", SrcVersion: "3.2.1-8"},
							{
								Name: "libgcc1", Version: "1:8-20180414-1ubuntu2", SrcName: "gcc-8",
								SrcVersion: "8-20180414-1ubuntu2",
							},
							{
								Name: "libgcrypt20", Version: "1.8.1-4ubuntu1.1", SrcName: "libgcrypt20",
								SrcVersion: "1.8.1-4ubuntu1.1",
							},
							{Name: "libgmp10", Version: "2:6.1.2+dfsg-2", SrcName: "gmp", SrcVersion: "2:6.1.2+dfsg-2"},
							{
								Name: "libgnutls30", Version: "3.5.18-1ubuntu1", SrcName: "gnutls28",
								SrcVersion: "3.5.18-1ubuntu1",
							},
							{Name: "libgpg-error0", Version: "1.27-6", SrcName: "libgpg-error", SrcVersion: "1.27-6"},
							{Name: "libhogweed4", Version: "3.4-1", SrcName: "nettle", SrcVersion: "3.4-1"},
							{
								Name: "libidn2-0", Version: "2.0.4-1.1build2", SrcName: "libidn2",
								SrcVersion: "2.0.4-1.1build2",
							},
							{
								Name: "liblz4-1", Version: "0.0~r131-2ubuntu3", SrcName: "lz4",
								SrcVersion: "0.0~r131-2ubuntu3",
							},
							{
								Name: "liblzma5", Version: "5.1.1alpha+20120614-2+b3", SrcName: "xz-utils",
								SrcVersion: "5.1.1alpha+20120614-2",
							},
							{
								Name: "libmount1", Version: "2.31.1-0.4ubuntu3.1", SrcName: "util-linux",
								SrcVersion: "2.31.1-0.4ubuntu3.1",
							},
							{
								Name: "libncurses5", Version: "6.1-1ubuntu1.18.04", SrcName: "ncurses",
								SrcVersion: "6.1-1ubuntu1.18.04",
							},
							{
								Name: "libncursesw5", Version: "6.1-1ubuntu1.18.04", SrcName: "ncurses",
								SrcVersion: "6.1-1ubuntu1.18.04",
							},
							{Name: "libnettle6", Version: "3.4-1", SrcName: "nettle", SrcVersion: "3.4-1"},
							{Name: "libp11-kit0", Version: "0.23.9-2", SrcName: "p11-kit", SrcVersion: "0.23.9-2"},
							{
								Name: "libpam-modules", Version: "1.1.8-3.6ubuntu2", SrcName: "pam",
								SrcVersion: "1.1.8-3.6ubuntu2",
							},
							{
								Name: "libpam-modules-bin", Version: "1.1.8-3.6ubuntu2", SrcName: "pam",
								SrcVersion: "1.1.8-3.6ubuntu2",
							},
							{
								Name: "libpam-runtime", Version: "1.1.8-3.6ubuntu2", SrcName: "pam",
								SrcVersion: "1.1.8-3.6ubuntu2",
							},
							{
								Name: "libpam0g", Version: "1.1.8-3.6ubuntu2", SrcName: "pam",
								SrcVersion: "1.1.8-3.6ubuntu2",
							},
							{Name: "libpcre3", Version: "2:8.39-9", SrcName: "pcre3", SrcVersion: "2:8.39-9"},
							{
								Name: "libprocps6", Version: "2:3.3.12-3ubuntu1.1", SrcName: "procps",
								SrcVersion: "2:3.3.12-3ubuntu1.1",
							},
							{
								Name: "libseccomp2", Version: "2.3.1-2.1ubuntu4", SrcName: "libseccomp",
								SrcVersion: "2.3.1-2.1ubuntu4",
							},
							{
								Name: "libselinux1", Version: "2.7-2build2", SrcName: "libselinux",
								SrcVersion: "2.7-2build2",
							},
							{
								Name: "libsemanage-common", Version: "2.7-2build2", SrcName: "libsemanage",
								SrcVersion: "2.7-2build2",
							},
							{
								Name: "libsemanage1", Version: "2.7-2build2", SrcName: "libsemanage",
								SrcVersion: "2.7-2build2",
							},
							{Name: "libsepol1", Version: "2.7-1", SrcName: "libsepol", SrcVersion: "2.7-1"},
							{
								Name: "libsmartcols1", Version: "2.31.1-0.4ubuntu3.1", SrcName: "util-linux",
								SrcVersion: "2.31.1-0.4ubuntu3.1",
							},
							{Name: "libss2", Version: "1.44.1-1", SrcName: "e2fsprogs", SrcVersion: "1.44.1-1"},
							{
								Name: "libstdc++6", Version: "8-20180414-1ubuntu2", SrcName: "gcc-8",
								SrcVersion: "8-20180414-1ubuntu2",
							},
							{
								Name: "libsystemd0", Version: "237-3ubuntu10.3", SrcName: "systemd",
								SrcVersion: "237-3ubuntu10.3",
							},
							{Name: "libtasn1-6", Version: "4.13-2", SrcName: "libtasn1-6", SrcVersion: "4.13-2"},
							{
								Name: "libtinfo5", Version: "6.1-1ubuntu1.18.04", SrcName: "ncurses",
								SrcVersion: "6.1-1ubuntu1.18.04",
							},
							{
								Name: "libudev1", Version: "237-3ubuntu10.3", SrcName: "systemd",
								SrcVersion: "237-3ubuntu10.3",
							},
							{
								Name: "libunistring2", Version: "0.9.9-0ubuntu1", SrcName: "libunistring",
								SrcVersion: "0.9.9-0ubuntu1",
							},
							{Name: "libustr-1.0-1", Version: "1.0.4-3+b2", SrcName: "ustr", SrcVersion: "1.0.4-3"},
							{
								Name: "libuuid1", Version: "2.31.1-0.4ubuntu3.1", SrcName: "util-linux",
								SrcVersion: "2.31.1-0.4ubuntu3.1",
							},
							{
								Name: "libzstd1", Version: "1.3.3+dfsg-2ubuntu1", SrcName: "libzstd",
								SrcVersion: "1.3.3+dfsg-2ubuntu1",
							},
							{Name: "login", Version: "1:4.5-1ubuntu1", SrcName: "shadow", SrcVersion: "1:4.5-1ubuntu1"},
							{
								Name: "lsb-base", Version: "9.20170808ubuntu1", SrcName: "lsb",
								SrcVersion: "9.20170808ubuntu1",
							},
							{Name: "mawk", Version: "1.3.3-17ubuntu3", SrcName: "mawk", SrcVersion: "1.3.3-17ubuntu3"},
							{
								Name: "mount", Version: "2.31.1-0.4ubuntu3.1", SrcName: "util-linux",
								SrcVersion: "2.31.1-0.4ubuntu3.1",
							},
							{
								Name: "ncurses-base", Version: "6.1-1ubuntu1.18.04", SrcName: "ncurses",
								SrcVersion: "6.1-1ubuntu1.18.04",
							},
							{
								Name: "ncurses-bin", Version: "6.1-1ubuntu1.18.04", SrcName: "ncurses",
								SrcVersion: "6.1-1ubuntu1.18.04",
							},
							{
								Name: "passwd", Version: "1:4.5-1ubuntu1", SrcName: "shadow",
								SrcVersion: "1:4.5-1ubuntu1",
							},
							{
								Name: "perl-base", Version: "5.26.1-6ubuntu0.2", SrcName: "perl",
								SrcVersion: "5.26.1-6ubuntu0.2",
							},
							{
								Name: "procps", Version: "2:3.3.12-3ubuntu1.1", SrcName: "procps",
								SrcVersion: "2:3.3.12-3ubuntu1.1",
							},
							{Name: "sed", Version: "4.4-2", SrcName: "sed", SrcVersion: "4.4-2"},
							{
								Name: "sensible-utils", Version: "0.0.12", SrcName: "sensible-utils",
								SrcVersion: "0.0.12",
							},
							{
								Name: "sysvinit-utils", Version: "2.88dsf-59.10ubuntu1", SrcName: "sysvinit",
								SrcVersion: "2.88dsf-59.10ubuntu1",
							},
							{Name: "tar", Version: "1.29b-2", SrcName: "tar", SrcVersion: "1.29b-2"},
							{
								Name: "ubuntu-keyring", Version: "2018.02.28", SrcName: "ubuntu-keyring",
								SrcVersion: "2018.02.28",
							},
							{
								Name: "util-linux", Version: "2.31.1-0.4ubuntu3.1", SrcName: "util-linux",
								SrcVersion: "2.31.1-0.4ubuntu3.1",
							},
							{
								Name: "zlib1g", Version: "1:1.2.11.dfsg-0ubuntu2", SrcName: "zlib",
								SrcVersion: "1:1.2.11.dfsg-0ubuntu2",
							},
						},
					},
				},
			},
		},
		{
			name:     "corrupsed",
			testFile: "./testdata/corrupsed",
			filePath: "var/lib/dpkg/status",
			want: &analyzer.AnalysisResult{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/dpkg/status",
						Packages: []types.Package{
							{
								Name: "libgcc1", Version: "1:5.1.1-12ubuntu1", SrcName: "gcc-5",
								SrcVersion: "5.1.1-12ubuntu1",
							},
							{
								Name: "libpam-modules-bin", Version: "1.1.8-3.1ubuntu3", SrcName: "pam",
								SrcVersion: "1.1.8-3.1ubuntu3",
							},
							{
								Name: "libpam-runtime", Version: "1.1.8-3.1ubuntu3", SrcName: "pam",
								SrcVersion: "1.1.8-3.1ubuntu3",
							},
							{
								Name: "makedev", Version: "2.3.1-93ubuntu1", SrcName: "makedev",
								SrcVersion: "2.3.1-93ubuntu1",
							},
						},
					},
				},
			},
		},
		{
			name:     "only apt",
			testFile: "./testdata/dpkg_apt",
			filePath: "var/lib/dpkg/status.d/apt",
			want: &analyzer.AnalysisResult{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/dpkg/status.d/apt",
						Packages: []types.Package{
							{Name: "apt", Version: "1.6.3ubuntu0.1", SrcName: "apt", SrcVersion: "1.6.3ubuntu0.1"},
						},
					},
				},
			},
		},
		{
			name:     "info list",
			testFile: "./testdata/bash.list",
			filePath: "var/lib/dpkg/info/tar.list",
			want: &analyzer.AnalysisResult{
				SystemInstalledFiles: []string{
					"/bin/tar",
					"/etc",
					"/usr/lib/mime/packages/tar",
					"/usr/sbin/rmt-tar",
					"/usr/sbin/tarcat",
					"/usr/share/doc/tar/AUTHORS",
					"/usr/share/doc/tar/NEWS.gz",
					"/usr/share/doc/tar/README.Debian",
					"/usr/share/doc/tar/THANKS.gz",
					"/usr/share/doc/tar/changelog.Debian.gz",
					"/usr/share/doc/tar/copyright",
					"/usr/share/man/man1/tar.1.gz",
					"/usr/share/man/man1/tarcat.1.gz",
					"/usr/share/man/man8/rmt-tar.8.gz",
					"/etc/rmt",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.testFile)
			require.NoError(t, err)
			defer f.Close()

			a := dpkgAnalyzer{}
			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.filePath,
				Content:  f,
			})

			// Sort the result for consistency
			for i := range got.PackageInfos {
				got.PackageInfos[i].Packages = sortPkgs(got.PackageInfos[i].Packages)
			}

			assert.Equal(t, tt.wantErr, err != nil, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func sortPkgs(pkgs []types.Package) []types.Package {
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Version < pkgs[j].Version
	})
	return pkgs
}

func Test_dpkgAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "status",
			filePath: "var/lib/dpkg/status",
			want:     true,
		},
		{
			name:     "status dir",
			filePath: "var/lib/dpkg/status.d/gcc",
			want:     true,
		},
		{
			name:     "list file",
			filePath: "var/lib/dpkg/info/bash.list",
			want:     true,
		},
		{
			name:     "sad path",
			filePath: "var/lib/dpkg/status/bash.list",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := dpkgAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
