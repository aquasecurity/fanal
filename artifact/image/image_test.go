package image_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	_ "github.com/aquasecurity/fanal/analyzer/all"
	"github.com/aquasecurity/fanal/analyzer/config"
	image2 "github.com/aquasecurity/fanal/artifact/image"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/hook"
	"github.com/aquasecurity/fanal/image"
	"github.com/aquasecurity/fanal/types"
	depTypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestArtifact_Inspect(t *testing.T) {
	tests := []struct {
		name                    string
		imagePath               string
		disableAnalyzers        []analyzer.Type
		disableHooks            []hook.Type
		missingBlobsExpectation cache.ArtifactCacheMissingBlobsExpectation
		putBlobExpectations     []cache.ArtifactCachePutBlobExpectation
		putArtifactExpectations []cache.ArtifactCachePutArtifactExpectation
		want                    types.ArtifactReference
		wantErr                 string
	}{
		{
			name:      "happy path",
			imagePath: "../../test/testdata/alpine-311.tar.gz",
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:d2b38afccf21751162a2c5d632f095290c96ab726642c1586d90f94cd8eb30bb",
					BlobIDs:    []string{"sha256:73e3d0ffa0ca4556a4c81486db8b5030de816d8211c9f8961ddbf2d81bb738f6"},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingArtifact: true,
					MissingBlobIDs:  []string{"sha256:73e3d0ffa0ca4556a4c81486db8b5030de816d8211c9f8961ddbf2d81bb738f6"},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:73e3d0ffa0ca4556a4c81486db8b5030de816d8211c9f8961ddbf2d81bb738f6",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
							OS: &types.OS{
								Family: "alpine",
								Name:   "3.11.5",
							},
							PackageInfos: []types.PackageInfo{{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
									{Name: "alpine-baselayout", Version: "3.2.0-r3", SrcName: "alpine-baselayout", SrcVersion: "3.2.0-r3", License: "GPL-2.0-only"},
									{Name: "alpine-keys", Version: "2.1-r2", SrcName: "alpine-keys", SrcVersion: "2.1-r2", License: "MIT"},
									{Name: "apk-tools", Version: "2.10.4-r3", SrcName: "apk-tools", SrcVersion: "2.10.4-r3", License: "GPL2"},
									{Name: "busybox", Version: "1.31.1-r9", SrcName: "busybox", SrcVersion: "1.31.1-r9", License: "GPL-2.0-only"},
									{Name: "ca-certificates-cacert", Version: "20191127-r1", SrcName: "ca-certificates", SrcVersion: "20191127-r1", License: "MPL-2.0 GPL-2.0-or-later"},
									{Name: "libc-utils", Version: "0.7.2-r0", SrcName: "libc-dev", SrcVersion: "0.7.2-r0", License: "BSD"},
									{Name: "libcrypto1.1", Version: "1.1.1d-r3", SrcName: "openssl", SrcVersion: "1.1.1d-r3", License: "OpenSSL"},
									{Name: "libssl1.1", Version: "1.1.1d-r3", SrcName: "openssl", SrcVersion: "1.1.1d-r3", License: "OpenSSL"},
									{Name: "libtls-standalone", Version: "2.9.1-r0", SrcName: "libtls-standalone", SrcVersion: "2.9.1-r0", License: "ISC"},
									{Name: "musl", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2", License: "MIT"},
									{Name: "musl-utils", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2", License: "MIT BSD GPL2+"},
									{Name: "scanelf", Version: "1.2.4-r0", SrcName: "pax-utils", SrcVersion: "1.2.4-r0", License: "GPL-2.0-only"},
									{Name: "ssl_client", Version: "1.31.1-r9", SrcName: "busybox", SrcVersion: "1.31.1-r9", License: "GPL-2.0-only"},
									{Name: "zlib", Version: "1.2.11-r3", SrcName: "zlib", SrcVersion: "1.2.11-r3", License: "Zlib"},
								},
							}},
							Applications:  []types.Application(nil),
							OpaqueDirs:    []string(nil),
							WhiteoutFiles: []string(nil),
							Size:          5591284,
						},
					},
					Returns: cache.ArtifactCachePutBlobReturns{},
				},
			},
			putArtifactExpectations: []cache.ArtifactCachePutArtifactExpectation{
				{
					Args: cache.ArtifactCachePutArtifactArgs{
						ArtifactID: "sha256:d2b38afccf21751162a2c5d632f095290c96ab726642c1586d90f94cd8eb30bb",
						ArtifactInfo: types.ArtifactInfo{
							SchemaVersion: 1,
							Architecture:  "amd64",
							Created:       time.Date(2020, 3, 23, 21, 19, 34, 196162891, time.UTC),
							DockerVersion: "18.09.7",
							OS:            "linux",
						},
					},
				},
			},
			want: types.ArtifactReference{
				Name:    "../../test/testdata/alpine-311.tar.gz",
				Type:    types.ArtifactContainerImage,
				ID:      "sha256:d2b38afccf21751162a2c5d632f095290c96ab726642c1586d90f94cd8eb30bb",
				BlobIDs: []string{"sha256:73e3d0ffa0ca4556a4c81486db8b5030de816d8211c9f8961ddbf2d81bb738f6"},
			},
		},
		{
			name:      "happy path: include lock files",
			imagePath: "../../test/testdata/vuln-image.tar.gz",
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:dd096dc1f5f4a50a3a257f3ae62e912d3dca448767104315eb01ad2ac019ec5e",
					BlobIDs: []string{
						"sha256:86a709d525c533ac543f00c7e9710588c45f98e6ef7a00bca37f115038784e87",
						"sha256:8052e60f6c6cca1ec029ef275fa333b3ab8566b7d8e57d163f182eb9d3371edf",
						"sha256:8bed22848d447994c41c6657c7f3166226f7166a04d4c65b57e4fe2a7af53fce",
						"sha256:0380dabe0bd9546f51e6684923f6cb85212dda13b4319c6a955062e01b51203b",
					},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingBlobIDs: []string{
						"sha256:86a709d525c533ac543f00c7e9710588c45f98e6ef7a00bca37f115038784e87",
						"sha256:8052e60f6c6cca1ec029ef275fa333b3ab8566b7d8e57d163f182eb9d3371edf",
						"sha256:8bed22848d447994c41c6657c7f3166226f7166a04d4c65b57e4fe2a7af53fce",
						"sha256:0380dabe0bd9546f51e6684923f6cb85212dda13b4319c6a955062e01b51203b",
					},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:86a709d525c533ac543f00c7e9710588c45f98e6ef7a00bca37f115038784e87",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							OS: &types.OS{
								Family: "debian",
								Name:   "9.9",
							},
							Size: 1805109,
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "var/lib/dpkg/status.d/base",
									Packages: []types.Package{
										{Name: "base-files", Version: "9.9+deb9u9", SrcName: "base-files", SrcVersion: "9.9+deb9u9"},
									},
								},
								{
									FilePath: "var/lib/dpkg/status.d/netbase",
									Packages: []types.Package{
										{Name: "netbase", Version: "5.4", SrcName: "netbase", SrcVersion: "5.4"},
									},
								},
								{
									FilePath: "var/lib/dpkg/status.d/tzdata",
									Packages: []types.Package{
										{Name: "tzdata", Version: "2019a-0+deb9u1", SrcName: "tzdata", SrcVersion: "2019a-0+deb9u1"},
									},
								},
							},
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:8052e60f6c6cca1ec029ef275fa333b3ab8566b7d8e57d163f182eb9d3371edf",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							PackageInfos: []types.PackageInfo{
								{
									FilePath: "var/lib/dpkg/status.d/libc6",
									Packages: []types.Package{
										{Name: "libc6", Version: "2.24-11+deb9u4", SrcName: "glibc", SrcVersion: "2.24-11+deb9u4"},
									},
								},
								{
									FilePath: "var/lib/dpkg/status.d/libssl1",
									Packages: []types.Package{
										{Name: "libssl1.1", Version: "1.1.0k-1~deb9u1", SrcName: "openssl", SrcVersion: "1.1.0k-1~deb9u1"},
									},
								},
								{
									FilePath: "var/lib/dpkg/status.d/openssl",
									Packages: []types.Package{
										{Name: "openssl", Version: "1.1.0k-1~deb9u1", SrcName: "openssl", SrcVersion: "1.1.0k-1~deb9u1"},
									},
								},
							},
							Size: 15065777,
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:8bed22848d447994c41c6657c7f3166226f7166a04d4c65b57e4fe2a7af53fce",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
							Size:          27103,
							Applications: []types.Application{{Type: "composer", FilePath: "php-app/composer.lock",
								Libraries: []types.LibraryInfo{
									{Library: depTypes.Library{Name: "guzzlehttp/guzzle", Version: "6.2.0"}},
									{Library: depTypes.Library{Name: "guzzlehttp/promises", Version: "v1.3.1"}},
									{Library: depTypes.Library{Name: "guzzlehttp/psr7", Version: "1.5.2"}},
									{Library: depTypes.Library{Name: "laravel/installer", Version: "v2.0.1"}},
									{Library: depTypes.Library{Name: "pear/log", Version: "1.13.1"}},
									{Library: depTypes.Library{Name: "pear/pear_exception", Version: "v1.0.0"}},
									{Library: depTypes.Library{Name: "psr/http-message", Version: "1.0.1"}},
									{Library: depTypes.Library{Name: "ralouphie/getallheaders", Version: "2.0.5"}},
									{Library: depTypes.Library{Name: "symfony/console", Version: "v4.2.7"}},
									{Library: depTypes.Library{Name: "symfony/contracts", Version: "v1.0.2"}},
									{Library: depTypes.Library{Name: "symfony/filesystem", Version: "v4.2.7"}},
									{Library: depTypes.Library{Name: "symfony/polyfill-ctype", Version: "v1.11.0"}},
									{Library: depTypes.Library{Name: "symfony/polyfill-mbstring", Version: "v1.11.0"}},
									{Library: depTypes.Library{Name: "symfony/process", Version: "v4.2.7"}},
								},
							}},
							OpaqueDirs: []string{"php-app/"},
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:0380dabe0bd9546f51e6684923f6cb85212dda13b4319c6a955062e01b51203b",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:a4595c43a874856bf95f3bfc4fbf78bbaa04c92c726276d4f64193a47ced0566",
							Applications: []types.Application{{Type: types.Bundler, FilePath: "ruby-app/Gemfile.lock",
								Libraries: []types.LibraryInfo{
									{Library: depTypes.Library{Name: "actioncable", Version: "5.2.3"}},
									{Library: depTypes.Library{Name: "actionmailer", Version: "5.2.3"}},
									{Library: depTypes.Library{Name: "actionpack", Version: "5.2.3"}},
									{Library: depTypes.Library{Name: "actionview", Version: "5.2.3"}},
									{Library: depTypes.Library{Name: "activejob", Version: "5.2.3"}},
									{Library: depTypes.Library{Name: "activemodel", Version: "5.2.3"}},
									{Library: depTypes.Library{Name: "activerecord", Version: "5.2.3"}},
									{Library: depTypes.Library{Name: "activestorage", Version: "5.2.3"}},
									{Library: depTypes.Library{Name: "activesupport", Version: "5.2.3"}},
									{Library: depTypes.Library{Name: "arel", Version: "9.0.0"}},
									{Library: depTypes.Library{Name: "ast", Version: "2.4.0"}},
									{Library: depTypes.Library{Name: "builder", Version: "3.2.3"}},
									{Library: depTypes.Library{Name: "coderay", Version: "1.1.2"}},
									{Library: depTypes.Library{Name: "concurrent-ruby", Version: "1.1.5"}},
									{Library: depTypes.Library{Name: "crass", Version: "1.0.4"}},
									{Library: depTypes.Library{Name: "dotenv", Version: "2.7.2"}},
									{Library: depTypes.Library{Name: "erubi", Version: "1.8.0"}},
									{Library: depTypes.Library{Name: "faker", Version: "1.9.3"}},
									{Library: depTypes.Library{Name: "globalid", Version: "0.4.2"}},
									{Library: depTypes.Library{Name: "i18n", Version: "1.6.0"}},
									{Library: depTypes.Library{Name: "jaro_winkler", Version: "1.5.2"}},
									{Library: depTypes.Library{Name: "json", Version: "2.2.0"}},
									{Library: depTypes.Library{Name: "loofah", Version: "2.2.3"}},
									{Library: depTypes.Library{Name: "mail", Version: "2.7.1"}},
									{Library: depTypes.Library{Name: "marcel", Version: "0.3.3"}},
									{Library: depTypes.Library{Name: "method_source", Version: "0.9.2"}},
									{Library: depTypes.Library{Name: "mimemagic", Version: "0.3.3"}},
									{Library: depTypes.Library{Name: "mini_mime", Version: "1.0.1"}},
									{Library: depTypes.Library{Name: "mini_portile2", Version: "2.4.0"}},
									{Library: depTypes.Library{Name: "minitest", Version: "5.11.3"}},
									{Library: depTypes.Library{Name: "nio4r", Version: "2.3.1"}},
									{Library: depTypes.Library{Name: "nokogiri", Version: "1.10.3"}},
									{Library: depTypes.Library{Name: "parallel", Version: "1.17.0"}},
									{Library: depTypes.Library{Name: "parser", Version: "2.6.3.0"}},
									{Library: depTypes.Library{Name: "pry", Version: "0.12.2"}},
									{Library: depTypes.Library{Name: "psych", Version: "3.1.0"}},
									{Library: depTypes.Library{Name: "rack", Version: "2.0.7"}},
									{Library: depTypes.Library{Name: "rack-test", Version: "1.1.0"}},
									{Library: depTypes.Library{Name: "rails", Version: "5.2.0"}},
									{Library: depTypes.Library{Name: "rails-dom-testing", Version: "2.0.3"}},
									{Library: depTypes.Library{Name: "rails-html-sanitizer", Version: "1.0.3"}},
									{Library: depTypes.Library{Name: "railties", Version: "5.2.3"}},
									{Library: depTypes.Library{Name: "rainbow", Version: "3.0.0"}},
									{Library: depTypes.Library{Name: "rake", Version: "12.3.2"}},
									{Library: depTypes.Library{Name: "rubocop", Version: "0.67.2"}},
									{Library: depTypes.Library{Name: "ruby-progressbar", Version: "1.10.0"}},
									{Library: depTypes.Library{Name: "sprockets", Version: "3.7.2"}},
									{Library: depTypes.Library{Name: "sprockets-rails", Version: "3.2.1"}},
									{Library: depTypes.Library{Name: "thor", Version: "0.20.3"}},
									{Library: depTypes.Library{Name: "thread_safe", Version: "0.3.6"}},
									{Library: depTypes.Library{Name: "tzinfo", Version: "1.2.5"}},
									{Library: depTypes.Library{Name: "unicode-display_width", Version: "1.5.0"}},
									{Library: depTypes.Library{Name: "websocket-driver", Version: "0.7.0"}},
									{Library: depTypes.Library{Name: "websocket-extensions", Version: "0.1.3"}},
								},
							}},
							OpaqueDirs: []string{
								"ruby-app/",
							},
							Size: 3619,
						},
					},
				},
			},
			want: types.ArtifactReference{
				Name: "../../test/testdata/vuln-image.tar.gz",
				Type: types.ArtifactContainerImage,
				ID:   "sha256:dd096dc1f5f4a50a3a257f3ae62e912d3dca448767104315eb01ad2ac019ec5e",
				BlobIDs: []string{
					"sha256:86a709d525c533ac543f00c7e9710588c45f98e6ef7a00bca37f115038784e87",
					"sha256:8052e60f6c6cca1ec029ef275fa333b3ab8566b7d8e57d163f182eb9d3371edf",
					"sha256:8bed22848d447994c41c6657c7f3166226f7166a04d4c65b57e4fe2a7af53fce",
					"sha256:0380dabe0bd9546f51e6684923f6cb85212dda13b4319c6a955062e01b51203b",
				},
			},
		},
		{
			name:             "happy path: disable analyzers",
			imagePath:        "../../test/testdata/vuln-image.tar.gz",
			disableAnalyzers: []analyzer.Type{analyzer.TypeDebian, analyzer.TypeDpkg, analyzer.TypeComposer, analyzer.TypeBundler},
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:dd096dc1f5f4a50a3a257f3ae62e912d3dca448767104315eb01ad2ac019ec5e",
					BlobIDs: []string{
						"sha256:f4b34b771cd347275066e030b4b3abbca373dc140793814291b40f5ffaa18b33",
						"sha256:e6709e0025b8fb8b35613c412a8c9134fc8af0b4466a2576f6ead11dc3e0e8e9",
						"sha256:b0062c664ecbebbf4946cbdafd718685001c6ebbd2f03a9e00deb8e7aad32f0d",
						"sha256:619968d449e812315d11d0b7409e3f8a8f5592d62d1dbbbe2ce0d90f4e4f0f7b",
					},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingBlobIDs: []string{
						"sha256:f4b34b771cd347275066e030b4b3abbca373dc140793814291b40f5ffaa18b33",
						"sha256:e6709e0025b8fb8b35613c412a8c9134fc8af0b4466a2576f6ead11dc3e0e8e9",
						"sha256:b0062c664ecbebbf4946cbdafd718685001c6ebbd2f03a9e00deb8e7aad32f0d",
						"sha256:619968d449e812315d11d0b7409e3f8a8f5592d62d1dbbbe2ce0d90f4e4f0f7b",
					},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:f4b34b771cd347275066e030b4b3abbca373dc140793814291b40f5ffaa18b33",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
							Size:          1805109,
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:e6709e0025b8fb8b35613c412a8c9134fc8af0b4466a2576f6ead11dc3e0e8e9",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:dffd9992ca398466a663c87c92cfea2a2db0ae0cf33fcb99da60eec52addbfc5",
							Size:          15065777,
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:b0062c664ecbebbf4946cbdafd718685001c6ebbd2f03a9e00deb8e7aad32f0d",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
							OpaqueDirs:    []string{"php-app/"},
							Size:          27103,
						},
					},
				},
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:619968d449e812315d11d0b7409e3f8a8f5592d62d1dbbbe2ce0d90f4e4f0f7b",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:a4595c43a874856bf95f3bfc4fbf78bbaa04c92c726276d4f64193a47ced0566",
							OpaqueDirs:    []string{"ruby-app/"},
							Size:          3619,
						},
					},
				},
			},
			want: types.ArtifactReference{
				Name: "../../test/testdata/vuln-image.tar.gz",
				Type: types.ArtifactContainerImage,
				ID:   "sha256:dd096dc1f5f4a50a3a257f3ae62e912d3dca448767104315eb01ad2ac019ec5e",
				BlobIDs: []string{
					"sha256:f4b34b771cd347275066e030b4b3abbca373dc140793814291b40f5ffaa18b33",
					"sha256:e6709e0025b8fb8b35613c412a8c9134fc8af0b4466a2576f6ead11dc3e0e8e9",
					"sha256:b0062c664ecbebbf4946cbdafd718685001c6ebbd2f03a9e00deb8e7aad32f0d",
					"sha256:619968d449e812315d11d0b7409e3f8a8f5592d62d1dbbbe2ce0d90f4e4f0f7b",
				},
			},
		},
		{
			name:      "sad path, MissingBlobs returns an error",
			imagePath: "../../test/testdata/alpine-311.tar.gz",
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:d2b38afccf21751162a2c5d632f095290c96ab726642c1586d90f94cd8eb30bb",
					BlobIDs:    []string{"sha256:73e3d0ffa0ca4556a4c81486db8b5030de816d8211c9f8961ddbf2d81bb738f6"},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					Err: xerrors.New("MissingBlobs failed"),
				},
			},
			wantErr: "MissingBlobs failed",
		},
		{
			name:      "sad path, PutBlob returns an error",
			imagePath: "../../test/testdata/alpine-311.tar.gz",
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:d2b38afccf21751162a2c5d632f095290c96ab726642c1586d90f94cd8eb30bb",
					BlobIDs:    []string{"sha256:73e3d0ffa0ca4556a4c81486db8b5030de816d8211c9f8961ddbf2d81bb738f6"},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingBlobIDs: []string{"sha256:73e3d0ffa0ca4556a4c81486db8b5030de816d8211c9f8961ddbf2d81bb738f6"},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:73e3d0ffa0ca4556a4c81486db8b5030de816d8211c9f8961ddbf2d81bb738f6",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
							OS: &types.OS{
								Family: "alpine",
								Name:   "3.11.5",
							},
							PackageInfos: []types.PackageInfo{{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
									{Name: "alpine-baselayout", Version: "3.2.0-r3", SrcName: "alpine-baselayout", SrcVersion: "3.2.0-r3", License: "GPL-2.0-only"},
									{Name: "alpine-keys", Version: "2.1-r2", SrcName: "alpine-keys", SrcVersion: "2.1-r2", License: "MIT"},
									{Name: "apk-tools", Version: "2.10.4-r3", SrcName: "apk-tools", SrcVersion: "2.10.4-r3", License: "GPL2"},
									{Name: "busybox", Version: "1.31.1-r9", SrcName: "busybox", SrcVersion: "1.31.1-r9", License: "GPL-2.0-only"},
									{Name: "ca-certificates-cacert", Version: "20191127-r1", SrcName: "ca-certificates", SrcVersion: "20191127-r1", License: "MPL-2.0 GPL-2.0-or-later"},
									{Name: "libc-utils", Version: "0.7.2-r0", SrcName: "libc-dev", SrcVersion: "0.7.2-r0", License: "BSD"},
									{Name: "libcrypto1.1", Version: "1.1.1d-r3", SrcName: "openssl", SrcVersion: "1.1.1d-r3", License: "OpenSSL"},
									{Name: "libssl1.1", Version: "1.1.1d-r3", SrcName: "openssl", SrcVersion: "1.1.1d-r3", License: "OpenSSL"},
									{Name: "libtls-standalone", Version: "2.9.1-r0", SrcName: "libtls-standalone", SrcVersion: "2.9.1-r0", License: "ISC"},
									{Name: "musl", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2", License: "MIT"},
									{Name: "musl-utils", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2", License: "MIT BSD GPL2+"},
									{Name: "scanelf", Version: "1.2.4-r0", SrcName: "pax-utils", SrcVersion: "1.2.4-r0", License: "GPL-2.0-only"},
									{Name: "ssl_client", Version: "1.31.1-r9", SrcName: "busybox", SrcVersion: "1.31.1-r9", License: "GPL-2.0-only"},
									{Name: "zlib", Version: "1.2.11-r3", SrcName: "zlib", SrcVersion: "1.2.11-r3", License: "Zlib"},
								},
							}},
							Applications:  []types.Application(nil),
							OpaqueDirs:    []string(nil),
							WhiteoutFiles: []string(nil),
							Size:          5591284,
						},
					},
					Returns: cache.ArtifactCachePutBlobReturns{
						Err: errors.New("put layer failed"),
					},
				},
			},
			wantErr: "put layer failed",
		},
		{
			name:      "sad path, PutArtifact returns an error",
			imagePath: "../../test/testdata/alpine-311.tar.gz",
			missingBlobsExpectation: cache.ArtifactCacheMissingBlobsExpectation{
				Args: cache.ArtifactCacheMissingBlobsArgs{
					ArtifactID: "sha256:d2b38afccf21751162a2c5d632f095290c96ab726642c1586d90f94cd8eb30bb",
					BlobIDs:    []string{"sha256:73e3d0ffa0ca4556a4c81486db8b5030de816d8211c9f8961ddbf2d81bb738f6"},
				},
				Returns: cache.ArtifactCacheMissingBlobsReturns{
					MissingArtifact: true,
					MissingBlobIDs:  []string{"sha256:73e3d0ffa0ca4556a4c81486db8b5030de816d8211c9f8961ddbf2d81bb738f6"},
				},
			},
			putBlobExpectations: []cache.ArtifactCachePutBlobExpectation{
				{
					Args: cache.ArtifactCachePutBlobArgs{
						BlobID: "sha256:73e3d0ffa0ca4556a4c81486db8b5030de816d8211c9f8961ddbf2d81bb738f6",
						BlobInfo: types.BlobInfo{
							SchemaVersion: 1,
							Digest:        "",
							DiffID:        "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
							OS: &types.OS{
								Family: "alpine",
								Name:   "3.11.5",
							},
							PackageInfos: []types.PackageInfo{{
								FilePath: "lib/apk/db/installed",
								Packages: []types.Package{
									{Name: "alpine-baselayout", Version: "3.2.0-r3", SrcName: "alpine-baselayout", SrcVersion: "3.2.0-r3", License: "GPL-2.0-only"},
									{Name: "alpine-keys", Version: "2.1-r2", SrcName: "alpine-keys", SrcVersion: "2.1-r2", License: "MIT"},
									{Name: "apk-tools", Version: "2.10.4-r3", SrcName: "apk-tools", SrcVersion: "2.10.4-r3", License: "GPL2"},
									{Name: "busybox", Version: "1.31.1-r9", SrcName: "busybox", SrcVersion: "1.31.1-r9", License: "GPL-2.0-only"},
									{Name: "ca-certificates-cacert", Version: "20191127-r1", SrcName: "ca-certificates", SrcVersion: "20191127-r1", License: "MPL-2.0 GPL-2.0-or-later"},
									{Name: "libc-utils", Version: "0.7.2-r0", SrcName: "libc-dev", SrcVersion: "0.7.2-r0", License: "BSD"},
									{Name: "libcrypto1.1", Version: "1.1.1d-r3", SrcName: "openssl", SrcVersion: "1.1.1d-r3", License: "OpenSSL"},
									{Name: "libssl1.1", Version: "1.1.1d-r3", SrcName: "openssl", SrcVersion: "1.1.1d-r3", License: "OpenSSL"},
									{Name: "libtls-standalone", Version: "2.9.1-r0", SrcName: "libtls-standalone", SrcVersion: "2.9.1-r0", License: "ISC"},
									{Name: "musl", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2", License: "MIT"},
									{Name: "musl-utils", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2", License: "MIT BSD GPL2+"},
									{Name: "scanelf", Version: "1.2.4-r0", SrcName: "pax-utils", SrcVersion: "1.2.4-r0", License: "GPL-2.0-only"},
									{Name: "ssl_client", Version: "1.31.1-r9", SrcName: "busybox", SrcVersion: "1.31.1-r9", License: "GPL-2.0-only"},
									{Name: "zlib", Version: "1.2.11-r3", SrcName: "zlib", SrcVersion: "1.2.11-r3", License: "Zlib"},
								},
							}},
							Applications:  []types.Application(nil),
							OpaqueDirs:    []string(nil),
							WhiteoutFiles: []string(nil),
							Size:          5591284,
						},
					},
					Returns: cache.ArtifactCachePutBlobReturns{},
				},
			},
			putArtifactExpectations: []cache.ArtifactCachePutArtifactExpectation{
				{
					Args: cache.ArtifactCachePutArtifactArgs{
						ArtifactID: "sha256:d2b38afccf21751162a2c5d632f095290c96ab726642c1586d90f94cd8eb30bb",
						ArtifactInfo: types.ArtifactInfo{
							SchemaVersion: 1,
							Architecture:  "amd64",
							Created:       time.Date(2020, 3, 23, 21, 19, 34, 196162891, time.UTC),
							DockerVersion: "18.09.7",
							OS:            "linux",
						},
					},
					Returns: cache.ArtifactCachePutArtifactReturns{
						Err: errors.New("put artifact failed"),
					},
				},
			},
			wantErr: "put artifact failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCache := new(cache.MockArtifactCache)
			mockCache.ApplyMissingBlobsExpectation(tt.missingBlobsExpectation)
			mockCache.ApplyPutBlobExpectations(tt.putBlobExpectations)
			mockCache.ApplyPutArtifactExpectations(tt.putArtifactExpectations)

			img, err := image.NewArchiveImage(tt.imagePath)
			require.NoError(t, err)

			a, err := image2.NewArtifact(img, mockCache, tt.disableAnalyzers, tt.disableHooks, config.ScannerOption{})
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			} else {
				require.NoError(t, err, tt.name)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
