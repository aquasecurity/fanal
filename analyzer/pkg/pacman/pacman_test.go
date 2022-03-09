package pacman

import (
	"context"
	"os"
	"testing"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_pacmanAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name     string
		testFile string
		filepath string
		want     *analyzer.AnalysisResult
	}{
		{
			name:     "valid desc",
			testFile: "./testdata/bash-5.1.008-1/desc",
			filepath: "var/lib/pacman/local/bash-5.1.008-1/desc",
			want: &analyzer.AnalysisResult{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/pacman/local/bash-5.1.008-1/desc",
						Packages: []types.Package{
							{Name: "bash", Version: "5.1.008", Release: "1", SrcName: "bash", SrcVersion: "5.1.008", SrcRelease: "1", Arch: "x86_64", License: "GPL"},
						},
					},
				},
			},
		},
		{
			name:     "valid files",
			testFile: "./testdata/bash-5.1.008-1/files",
			filepath: "var/lib/pacman/local/bash-5.1.008-1/files",
			want: &analyzer.AnalysisResult{
				SystemInstalledFiles: []string{
					"etc/bash.bash_logout",
					"etc/bash.bashrc",
					"etc/skel/.bash_logout",
					"etc/skel/.bash_profile",
					"etc/skel/.bashrc",
					"usr/bin/bash",
					"usr/bin/bashbug",
					"usr/bin/sh",
					"usr/include/bash/alias.h",
					"usr/include/bash/array.h",
					"usr/include/bash/arrayfunc.h",
					"usr/include/bash/assoc.h",
					"usr/include/bash/bashansi.h",
					"usr/include/bash/bashintl.h",
					"usr/include/bash/bashjmp.h",
					"usr/include/bash/bashtypes.h",
					"usr/include/bash/builtins.h",
					"usr/include/bash/builtins/bashgetopt.h",
					"usr/include/bash/builtins/builtext.h",
					"usr/include/bash/builtins/common.h",
					"usr/include/bash/builtins/getopt.h",
					"usr/include/bash/command.h",
					"usr/include/bash/config-bot.h",
					"usr/include/bash/config-top.h",
					"usr/include/bash/config.h",
					"usr/include/bash/conftypes.h",
					"usr/include/bash/dispose_cmd.h",
					"usr/include/bash/error.h",
					"usr/include/bash/externs.h",
					"usr/include/bash/general.h",
					"usr/include/bash/hashlib.h",
					"usr/include/bash/include/ansi_stdlib.h",
					"usr/include/bash/include/chartypes.h",
					"usr/include/bash/include/filecntl.h",
					"usr/include/bash/include/gettext.h",
					"usr/include/bash/include/maxpath.h",
					"usr/include/bash/include/memalloc.h",
					"usr/include/bash/include/ocache.h",
					"usr/include/bash/include/posixdir.h",
					"usr/include/bash/include/posixjmp.h",
					"usr/include/bash/include/posixstat.h",
					"usr/include/bash/include/posixtime.h",
					"usr/include/bash/include/posixwait.h",
					"usr/include/bash/include/shmbchar.h",
					"usr/include/bash/include/shmbutil.h",
					"usr/include/bash/include/shtty.h",
					"usr/include/bash/include/stat-time.h",
					"usr/include/bash/include/stdc.h",
					"usr/include/bash/include/systimes.h",
					"usr/include/bash/include/typemax.h",
					"usr/include/bash/include/unionwait.h",
					"usr/include/bash/jobs.h",
					"usr/include/bash/make_cmd.h",
					"usr/include/bash/pathnames.h",
					"usr/include/bash/quit.h",
					"usr/include/bash/shell.h",
					"usr/include/bash/sig.h",
					"usr/include/bash/siglist.h",
					"usr/include/bash/signames.h",
					"usr/include/bash/subst.h",
					"usr/include/bash/syntax.h",
					"usr/include/bash/unwind_prot.h",
					"usr/include/bash/variables.h",
					"usr/include/bash/version.h",
					"usr/include/bash/xmalloc.h",
					"usr/include/bash/y.tab.h",
					"usr/lib/bash/Makefile.inc",
					"usr/lib/bash/accept",
					"usr/lib/bash/basename",
					"usr/lib/bash/csv",
					"usr/lib/bash/cut",
					"usr/lib/bash/dirname",
					"usr/lib/bash/fdflags",
					"usr/lib/bash/finfo",
					"usr/lib/bash/head",
					"usr/lib/bash/id",
					"usr/lib/bash/ln",
					"usr/lib/bash/loadables.h",
					"usr/lib/bash/logname",
					"usr/lib/bash/mkdir",
					"usr/lib/bash/mkfifo",
					"usr/lib/bash/mktemp",
					"usr/lib/bash/mypid",
					"usr/lib/bash/pathchk",
					"usr/lib/bash/print",
					"usr/lib/bash/printenv",
					"usr/lib/bash/push",
					"usr/lib/bash/realpath",
					"usr/lib/bash/rm",
					"usr/lib/bash/rmdir",
					"usr/lib/bash/seq",
					"usr/lib/bash/setpgid",
					"usr/lib/bash/sleep",
					"usr/lib/bash/strftime",
					"usr/lib/bash/sync",
					"usr/lib/bash/tee",
					"usr/lib/bash/truefalse",
					"usr/lib/bash/tty",
					"usr/lib/bash/uname",
					"usr/lib/bash/unlink",
					"usr/lib/bash/whoami",
					"usr/lib/pkgconfig/bash.pc",
					"usr/share/doc/bash/CHANGES",
					"usr/share/doc/bash/COMPAT",
					"usr/share/doc/bash/FAQ",
					"usr/share/doc/bash/INTRO",
					"usr/share/doc/bash/NEWS",
					"usr/share/doc/bash/POSIX",
					"usr/share/doc/bash/RBASH",
					"usr/share/doc/bash/README",
					"usr/share/doc/bash/bash.html",
					"usr/share/doc/bash/bashref.html",
					"usr/share/info/bash.info.gz",
					"usr/share/locale/af/LC_MESSAGES/bash.mo",
					"usr/share/locale/bg/LC_MESSAGES/bash.mo",
					"usr/share/locale/ca/LC_MESSAGES/bash.mo",
					"usr/share/locale/cs/LC_MESSAGES/bash.mo",
					"usr/share/locale/da/LC_MESSAGES/bash.mo",
					"usr/share/locale/de/LC_MESSAGES/bash.mo",
					"usr/share/locale/el/LC_MESSAGES/bash.mo",
					"usr/share/locale/en@boldquot/LC_MESSAGES/bash.mo",
					"usr/share/locale/en@quot/LC_MESSAGES/bash.mo",
					"usr/share/locale/eo/LC_MESSAGES/bash.mo",
					"usr/share/locale/es/LC_MESSAGES/bash.mo",
					"usr/share/locale/et/LC_MESSAGES/bash.mo",
					"usr/share/locale/fi/LC_MESSAGES/bash.mo",
					"usr/share/locale/fr/LC_MESSAGES/bash.mo",
					"usr/share/locale/ga/LC_MESSAGES/bash.mo",
					"usr/share/locale/gl/LC_MESSAGES/bash.mo",
					"usr/share/locale/hr/LC_MESSAGES/bash.mo",
					"usr/share/locale/hu/LC_MESSAGES/bash.mo",
					"usr/share/locale/id/LC_MESSAGES/bash.mo",
					"usr/share/locale/it/LC_MESSAGES/bash.mo",
					"usr/share/locale/ja/LC_MESSAGES/bash.mo",
					"usr/share/locale/ko/LC_MESSAGES/bash.mo",
					"usr/share/locale/lt/LC_MESSAGES/bash.mo",
					"usr/share/locale/nb/LC_MESSAGES/bash.mo",
					"usr/share/locale/nl/LC_MESSAGES/bash.mo",
					"usr/share/locale/pl/LC_MESSAGES/bash.mo",
					"usr/share/locale/pt/LC_MESSAGES/bash.mo",
					"usr/share/locale/pt_BR/LC_MESSAGES/bash.mo",
					"usr/share/locale/ro/LC_MESSAGES/bash.mo",
					"usr/share/locale/ru/LC_MESSAGES/bash.mo",
					"usr/share/locale/sk/LC_MESSAGES/bash.mo",
					"usr/share/locale/sl/LC_MESSAGES/bash.mo",
					"usr/share/locale/sr/LC_MESSAGES/bash.mo",
					"usr/share/locale/sv/LC_MESSAGES/bash.mo",
					"usr/share/locale/tr/LC_MESSAGES/bash.mo",
					"usr/share/locale/uk/LC_MESSAGES/bash.mo",
					"usr/share/locale/vi/LC_MESSAGES/bash.mo",
					"usr/share/locale/zh_CN/LC_MESSAGES/bash.mo",
					"usr/share/locale/zh_TW/LC_MESSAGES/bash.mo",
					"usr/share/man/man1/bash.1.gz",
					"usr/share/man/man1/bashbug.1.gz",
				},
			},
		},
		{
			name:     "valid mtree",
			testFile: "./testdata/bash-5.1.008-1/mtree",
			filepath: "var/lib/pacman/local/bash-5.1.008-1/mtree",
			want:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.testFile)
			require.NoError(t, err)
			defer f.Close()

			ctx := context.Background()

			a := pacmanAnalyzer{}
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.filepath,
				Content:  f,
			})
			require.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}
