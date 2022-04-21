package nodejs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/types"
)

func Test_systemFileFilterHook_Hook(t *testing.T) {
	tests := []struct {
		name string
		blob *types.BlobInfo
		want *types.BlobInfo
	}{
		{
			name: "happy path",
			blob: &types.BlobInfo{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/rpm/Packages",
						Packages: []types.Package{
							{
								Name:    "python",
								Version: "2.7.5",
								Release: "89.el7",
							},
							{
								Name:    "python-libs",
								Version: "2.7.5",
								Release: "89.el7",
							},
						},
					},
				},
				Applications: []types.Application{
					{
						Type:     types.Pipenv,
						FilePath: "app/Pipfile.lock",
						Libraries: []types.Package{
							{
								Name:    "django",
								Version: "3.1.2",
							},
						},
					},
					{
						Type: types.PythonPkg,
						Libraries: []types.Package{
							{
								Name:     "python",
								Version:  "2.7.5",
								FilePath: "usr/lib64/python2.7/lib-dynload/Python-2.7.5-py2.7.egg-info",
							},
							{
								Name:     "pycurl",
								Version:  "7.19.0",
								FilePath: "usr/lib64/python2.7/site-packages/pycurl-7.19.0-py2.7.egg-info",
							},
						},
					},
					{
						Type:     types.PythonPkg,
						FilePath: "usr/lib64/python2.7/wsgiref.egg-info",
						Libraries: []types.Package{
							{
								Name:    "wsgiref",
								Version: "0.1.2",
							},
						},
					},
					{
						Type:     types.GoBinary,
						FilePath: "usr/local/bin/goBinariryFile",
						Libraries: []types.Package{
							{
								Name:     "cloud.google.com/go",
								Version:  "v0.81.0",
								FilePath: "",
							},
						},
					},
				},
				SystemFiles: []string{
					"/",
					"/usr/bin/pydoc",
					"/usr/bin/python",
					"/usr/bin/python2",
					"/usr/bin/python2.7",
					"/usr/libexec/platform-python",
					"/usr/share/doc/python-2.7.5",
					"/usr/share/doc/python-2.7.5/LICENSE",
					"/usr/share/doc/python-2.7.5/README",
					"/usr/share/man/man1/python.1.gz",
					"/usr/share/man/man1/python2.1.gz",
					"/usr/share/man/man1/python2.7.1.gz",
					"/usr/lib64/python2.7/distutils/command/install_egg_info.py",
					"/usr/lib64/python2.7/distutils/command/install_egg_info.pyc",
					"/usr/lib64/python2.7/distutils/command/install_egg_info.pyo",
					"/usr/lib64/python2.7/lib-dynload/Python-2.7.5-py2.7.egg-info",
					"usr/lib64/python2.7/wsgiref.egg-info", // without the leading slash
				},
				CustomResources: []types.CustomResource{
					{
						FilePath: "usr/bin/pydoc",
						Data:     "remove",
					},
					{
						FilePath: "usr/bin/pydoc/needed",
						Data:     "shouldNotRemove",
					},
				},
			},
			want: &types.BlobInfo{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/rpm/Packages",
						Packages: []types.Package{
							{
								Name:    "python",
								Version: "2.7.5",
								Release: "89.el7",
							},
							{
								Name:    "python-libs",
								Version: "2.7.5",
								Release: "89.el7",
							},
						},
					},
				},
				Applications: []types.Application{
					{
						Type:     types.Pipenv,
						FilePath: "app/Pipfile.lock",
						Libraries: []types.Package{
							{
								Name:    "django",
								Version: "3.1.2",
							},
						},
					},
					{
						Type: types.PythonPkg,
						Libraries: []types.Package{
							{
								Name:     "pycurl",
								Version:  "7.19.0",
								FilePath: "usr/lib64/python2.7/site-packages/pycurl-7.19.0-py2.7.egg-info",
							},
						},
					},
					{
						Type:     types.GoBinary,
						FilePath: "usr/local/bin/goBinariryFile",
						Libraries: []types.Package{
							{
								Name:    "cloud.google.com/go",
								Version: "v0.81.0",
							},
						},
					},
				},
				CustomResources: []types.CustomResource{
					{
						FilePath: "usr/bin/pydoc/needed",
						Data:     "shouldNotRemove",
						Layer:    types.Layer{},
					},
				},
			},
		},
		{
			name: "distoless",
			blob: &types.BlobInfo{
				Applications: []types.Application{
					{
						Type:     types.PythonPkg,
						FilePath: "usr/lib/python2.7/lib-dynload/Python-2.7.egg-info",
						Libraries: []types.Package{
							{
								Name:     "python",
								Version:  "2.7.14",
								FilePath: "usr/lib/python2.7/lib-dynload/Python-2.7.egg-info",
							},
						},
					},
				},
			},
			want: &types.BlobInfo{},
		},
		{
			name: "go binaries",
			blob: &types.BlobInfo{
				Applications: []types.Application{
					{
						Type:     types.GoBinary,
						FilePath: "usr/local/bin/goreleaser",
						Libraries: []types.Package{
							{
								Name:    "github.com/sassoftware/go-rpmutils",
								Version: "v0.0.0-20190420191620-a8f1baeba37b",
							},
						},
					},
				},
				SystemFiles: []string{
					"usr/local/bin/goreleaser",
				},
			},
			want: &types.BlobInfo{},
		},
		{
			name: "Rust will not be skipped",
			blob: &types.BlobInfo{
				Applications: []types.Application{
					{
						Type:     types.Cargo,
						FilePath: "app/Cargo.lock",
						Libraries: []types.Package{
							{
								Name:    "ghash",
								Version: "0.4.4",
							},
						},
					},
				},
				SystemFiles: []string{
					"app/Cargo.lock",
				},
			},
			want: &types.BlobInfo{
				Applications: []types.Application{
					{
						Type:     types.Cargo,
						FilePath: "app/Cargo.lock",
						Libraries: []types.Package{
							{
								Name:    "ghash",
								Version: "0.4.4",
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := systemFileFilterHook{}
			err := h.Hook(tt.blob)
			require.NoError(t, err)
			assert.Equal(t, tt.want, tt.blob)
		})
	}
}
