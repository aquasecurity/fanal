package apk

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/knqyf263/fanal/extractor"

	"github.com/kylelemons/godebug/pretty"

	"github.com/knqyf263/fanal/analyzer"
)

func TestAnalyze(t *testing.T) {
	var tests = map[string]struct {
		targetOS            analyzer.OS
		fileMap             extractor.FileMap
		apkIndexArchivePath string
		expected            []analyzer.Package
	}{
		"old": {
			targetOS: analyzer.OS{
				Family: "alpine",
				Name:   "3.9.1",
			},
			fileMap: extractor.FileMap{
				"/config": extractor.FileData{
					Body:     []byte(`{"architecture":"amd64","config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","PHPIZE_DEPS=autoconf \t\tdpkg-dev dpkg \t\tfile \t\tg++ \t\tgcc \t\tlibc-dev \t\tmake \t\tpkgconf \t\tre2c","PHP_INI_DIR=/usr/local/etc/php","PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2","PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2","PHP_LDFLAGS=-Wl,-O1 -Wl,--hash-style=both -pie","GPG_KEYS=1729F83938DA44E27BA0F4D3DBDB397470D12172 B1B44D8F021E4E2D6021E995DC9FF8D3EE5AF27F","PHP_VERSION=7.2.11","PHP_URL=https://secure.php.net/get/php-7.2.11.tar.xz/from/this/mirror","PHP_ASC_URL=https://secure.php.net/get/php-7.2.11.tar.xz.asc/from/this/mirror","PHP_SHA256=da1a705c0bc46410e330fc6baa967666c8cd2985378fb9707c01a8e33b01d985","PHP_MD5=","COMPOSER_ALLOW_SUPERUSER=1","COMPOSER_HOME=/tmp","COMPOSER_VERSION=1.7.2"],"Cmd":["composer"],"ArgsEscaped":true,"Image":"sha256:ad8c55ed62ca1f439bd600c7251de347926ca901ab7f52a93d8fba743ef397c6","Volumes":null,"WorkingDir":"/app","Entrypoint":["/bin/sh","/docker-entrypoint.sh"],"OnBuild":[],"Labels":null},"container":"f5b08762ace1af069127a337579acd51c415b919d736e6615b453a3c6fbf260d","container_config":{"Hostname":"f5b08762ace1","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","PHPIZE_DEPS=autoconf \t\tdpkg-dev dpkg \t\tfile \t\tg++ \t\tgcc \t\tlibc-dev \t\tmake \t\tpkgconf \t\tre2c","PHP_INI_DIR=/usr/local/etc/php","PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2","PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2","PHP_LDFLAGS=-Wl,-O1 -Wl,--hash-style=both -pie","GPG_KEYS=1729F83938DA44E27BA0F4D3DBDB397470D12172 B1B44D8F021E4E2D6021E995DC9FF8D3EE5AF27F","PHP_VERSION=7.2.11","PHP_URL=https://secure.php.net/get/php-7.2.11.tar.xz/from/this/mirror","PHP_ASC_URL=https://secure.php.net/get/php-7.2.11.tar.xz.asc/from/this/mirror","PHP_SHA256=da1a705c0bc46410e330fc6baa967666c8cd2985378fb9707c01a8e33b01d985","PHP_MD5=","COMPOSER_ALLOW_SUPERUSER=1","COMPOSER_HOME=/tmp","COMPOSER_VERSION=1.7.2"],"Cmd":["/bin/sh","-c","#(nop) ","CMD [\"composer\"]"],"ArgsEscaped":true,"Image":"sha256:ad8c55ed62ca1f439bd600c7251de347926ca901ab7f52a93d8fba743ef397c6","Volumes":null,"WorkingDir":"/app","Entrypoint":["/bin/sh","/docker-entrypoint.sh"],"OnBuild":[],"Labels":{}},"created":"2018-10-15T21:28:53.798628678Z","docker_version":"17.06.2-ce","history":[{"created":"2018-09-11T22:19:38.88529994Z","created_by":"/bin/sh -c #(nop) ADD file:49f9e47e678d868d5b023482aa8dded71276a241a665c4f8b55ca77269321b34 in / "},{"created":"2018-09-11T22:19:39.058628442Z","created_by":"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]","empty_layer":true},{"created":"2018-09-12T01:26:59.951316015Z","created_by":"/bin/sh -c #(nop)  ENV PHPIZE_DEPS=autoconf \t\tdpkg-dev dpkg \t\tfile \t\tg++ \t\tgcc \t\tlibc-dev \t\tmake \t\tpkgconf \t\tre2c","empty_layer":true},{"created":"2018-09-12T01:27:01.470388635Z","created_by":"/bin/sh -c apk add --no-cache --virtual .persistent-deps \t\tca-certificates \t\tcurl \t\ttar \t\txz \t\tlibressl"},{"created":"2018-09-12T01:27:02.432381785Z","created_by":"/bin/sh -c set -x \t\u0026\u0026 addgroup -g 82 -S www-data \t\u0026\u0026 adduser -u 82 -D -S -G www-data www-data"},{"created":"2018-09-12T01:27:02.715120309Z","created_by":"/bin/sh -c #(nop)  ENV PHP_INI_DIR=/usr/local/etc/php","empty_layer":true},{"created":"2018-09-12T01:27:03.655421341Z","created_by":"/bin/sh -c mkdir -p $PHP_INI_DIR/conf.d"},{"created":"2018-09-12T01:27:03.931799562Z","created_by":"/bin/sh -c #(nop)  ENV PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2","empty_layer":true},{"created":"2018-09-12T01:27:04.210945499Z","created_by":"/bin/sh -c #(nop)  ENV PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2","empty_layer":true},{"created":"2018-09-12T01:27:04.523116501Z","created_by":"/bin/sh -c #(nop)  ENV PHP_LDFLAGS=-Wl,-O1 -Wl,--hash-style=both -pie","empty_layer":true},{"created":"2018-09-12T01:27:04.795176159Z","created_by":"/bin/sh -c #(nop)  ENV GPG_KEYS=1729F83938DA44E27BA0F4D3DBDB397470D12172 B1B44D8F021E4E2D6021E995DC9FF8D3EE5AF27F","empty_layer":true},{"created":"2018-10-15T19:02:18.415761689Z","created_by":"/bin/sh -c #(nop)  ENV PHP_VERSION=7.2.11","empty_layer":true},{"created":"2018-10-15T19:02:18.599097853Z","created_by":"/bin/sh -c #(nop)  ENV PHP_URL=https://secure.php.net/get/php-7.2.11.tar.xz/from/this/mirror PHP_ASC_URL=https://secure.php.net/get/php-7.2.11.tar.xz.asc/from/this/mirror","empty_layer":true},{"created":"2018-10-15T19:02:18.782890412Z","created_by":"/bin/sh -c #(nop)  ENV PHP_SHA256=da1a705c0bc46410e330fc6baa967666c8cd2985378fb9707c01a8e33b01d985 PHP_MD5=","empty_layer":true},{"created":"2018-10-15T19:02:22.795846753Z","created_by":"/bin/sh -c set -xe; \t\tapk add --no-cache --virtual .fetch-deps \t\tgnupg \t\twget \t; \t\tmkdir -p /usr/src; \tcd /usr/src; \t\twget -O php.tar.xz \"$PHP_URL\"; \t\tif [ -n \"$PHP_SHA256\" ]; then \t\techo \"$PHP_SHA256 *php.tar.xz\" | sha256sum -c -; \tfi; \tif [ -n \"$PHP_MD5\" ]; then \t\techo \"$PHP_MD5 *php.tar.xz\" | md5sum -c -; \tfi; \t\tif [ -n \"$PHP_ASC_URL\" ]; then \t\twget -O php.tar.xz.asc \"$PHP_ASC_URL\"; \t\texport GNUPGHOME=\"$(mktemp -d)\"; \t\tfor key in $GPG_KEYS; do \t\t\tgpg --keyserver ha.pool.sks-keyservers.net --recv-keys \"$key\"; \t\tdone; \t\tgpg --batch --verify php.tar.xz.asc php.tar.xz; \t\tcommand -v gpgconf \u003e /dev/null \u0026\u0026 gpgconf --kill all; \t\trm -rf \"$GNUPGHOME\"; \tfi; \t\tapk del .fetch-deps"},{"created":"2018-10-15T19:02:23.071406376Z","created_by":"/bin/sh -c #(nop) COPY file:207c686e3fed4f71f8a7b245d8dcae9c9048d276a326d82b553c12a90af0c0ca in /usr/local/bin/ "},{"created":"2018-10-15T19:07:13.09339668Z","created_by":"/bin/sh -c set -xe \t\u0026\u0026 apk add --no-cache --virtual .build-deps \t\t$PHPIZE_DEPS \t\tcoreutils \t\tcurl-dev \t\tlibedit-dev \t\tlibressl-dev \t\tlibsodium-dev \t\tlibxml2-dev \t\tsqlite-dev \t\t\u0026\u0026 export CFLAGS=\"$PHP_CFLAGS\" \t\tCPPFLAGS=\"$PHP_CPPFLAGS\" \t\tLDFLAGS=\"$PHP_LDFLAGS\" \t\u0026\u0026 docker-php-source extract \t\u0026\u0026 cd /usr/src/php \t\u0026\u0026 gnuArch=\"$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)\" \t\u0026\u0026 ./configure \t\t--build=\"$gnuArch\" \t\t--with-config-file-path=\"$PHP_INI_DIR\" \t\t--with-config-file-scan-dir=\"$PHP_INI_DIR/conf.d\" \t\t\t\t--enable-option-checking=fatal \t\t\t\t--with-mhash \t\t\t\t--enable-ftp \t\t--enable-mbstring \t\t--enable-mysqlnd \t\t--with-sodium=shared \t\t\t\t--with-curl \t\t--with-libedit \t\t--with-openssl \t\t--with-zlib \t\t\t\t$(test \"$gnuArch\" = 's390x-linux-gnu' \u0026\u0026 echo '--without-pcre-jit') \t\t\t\t$PHP_EXTRA_CONFIGURE_ARGS \t\u0026\u0026 make -j \"$(nproc)\" \t\u0026\u0026 make install \t\u0026\u0026 { find /usr/local/bin /usr/local/sbin -type f -perm +0111 -exec strip --strip-all '{}' + || true; } \t\u0026\u0026 make clean \t\t\u0026\u0026 cp -v php.ini-* \"$PHP_INI_DIR/\" \t\t\u0026\u0026 cd / \t\u0026\u0026 docker-php-source delete \t\t\u0026\u0026 runDeps=\"$( \t\tscanelf --needed --nobanner --format '%n#p' --recursive /usr/local \t\t\t| tr ',' '\\n' \t\t\t| sort -u \t\t\t| awk 'system(\"[ -e /usr/local/lib/\" $1 \" ]\") == 0 { next } { print \"so:\" $1 }' \t)\" \t\u0026\u0026 apk add --no-cache --virtual .php-rundeps $runDeps \t\t\u0026\u0026 apk del .build-deps \t\t\u0026\u0026 pecl update-channels \t\u0026\u0026 rm -rf /tmp/pear ~/.pearrc"},{"created":"2018-10-15T19:07:13.722586262Z","created_by":"/bin/sh -c #(nop) COPY multi:2cdcedabcf5a3b9ae610fab7848e94bc2f64b4d85710d55fd6f79e44dacf73d8 in /usr/local/bin/ "},{"created":"2018-10-15T19:07:14.618087104Z","created_by":"/bin/sh -c docker-php-ext-enable sodium"},{"created":"2018-10-15T19:07:14.826981756Z","created_by":"/bin/sh -c #(nop)  ENTRYPOINT [\"docker-php-entrypoint\"]","empty_layer":true},{"created":"2018-10-15T19:07:15.010831572Z","created_by":"/bin/sh -c #(nop)  CMD [\"php\" \"-a\"]","empty_layer":true},{"created":"2018-10-15T21:28:21.919735971Z","created_by":"/bin/sh -c apk --no-cache add git subversion openssh mercurial tini bash patch"},{"created":"2018-10-15T21:28:22.611763893Z","created_by":"/bin/sh -c echo \"memory_limit=-1\" \u003e \"$PHP_INI_DIR/conf.d/memory-limit.ini\"  \u0026\u0026 echo \"date.timezone=${PHP_TIMEZONE:-UTC}\" \u003e \"$PHP_INI_DIR/conf.d/date_timezone.ini\""},{"created":"2018-10-15T21:28:50.224278478Z","created_by":"/bin/sh -c apk add --no-cache --virtual .build-deps zlib-dev  \u0026\u0026 docker-php-ext-install zip  \u0026\u0026 runDeps=\"$(     scanelf --needed --nobanner --format '%n#p' --recursive /usr/local/lib/php/extensions     | tr ',' '\\n'     | sort -u     | awk 'system(\"[ -e /usr/local/lib/\" $1 \" ]\") == 0 { next } { print \"so:\" $1 }'     )\"  \u0026\u0026 apk add --virtual .composer-phpext-rundeps $runDeps  \u0026\u0026 apk del .build-deps"},{"created":"2018-10-15T21:28:50.503010161Z","created_by":"/bin/sh -c #(nop)  ENV COMPOSER_ALLOW_SUPERUSER=1","empty_layer":true},{"created":"2018-10-15T21:28:50.775378559Z","created_by":"/bin/sh -c #(nop)  ENV COMPOSER_HOME=/tmp","empty_layer":true},{"created":"2018-10-15T21:28:51.035012363Z","created_by":"/bin/sh -c #(nop)  ENV COMPOSER_VERSION=1.7.2","empty_layer":true},{"created":"2018-10-15T21:28:52.491402624Z","created_by":"/bin/sh -c curl --silent --fail --location --retry 3 --output /tmp/installer.php --url https://raw.githubusercontent.com/composer/getcomposer.org/b107d959a5924af895807021fcef4ffec5a76aa9/web/installer  \u0026\u0026 php -r \"     \\$signature = '544e09ee996cdf60ece3804abc52599c22b1f40f4323403c44d44fdfdd586475ca9813a858088ffbc1f233e9b180f061';     \\$hash = hash('SHA384', file_get_contents('/tmp/installer.php'));     if (!hash_equals(\\$signature, \\$hash)) {         unlink('/tmp/installer.php');         echo 'Integrity check failed, installer is either corrupt or worse.' . PHP_EOL;         exit(1);     }\"  \u0026\u0026 php /tmp/installer.php --no-ansi --install-dir=/usr/bin --filename=composer --version=${COMPOSER_VERSION}  \u0026\u0026 composer --ansi --version --no-interaction  \u0026\u0026 rm -rf /tmp/* /tmp/.htaccess"},{"created":"2018-10-15T21:28:52.948859545Z","created_by":"/bin/sh -c #(nop) COPY file:295943a303e8f27de4302b6aa3687bce4b1d1392335efaaab9ecd37bec5ab4c5 in /docker-entrypoint.sh "},{"created":"2018-10-15T21:28:53.295399872Z","created_by":"/bin/sh -c #(nop) WORKDIR /app"},{"created":"2018-10-15T21:28:53.582920705Z","created_by":"/bin/sh -c #(nop)  ENTRYPOINT [\"/bin/sh\" \"/docker-entrypoint.sh\"]","empty_layer":true},{"created":"2018-10-15T21:28:53.798628678Z","created_by":"/bin/sh -c #(nop)  CMD [\"composer\"]","empty_layer":true}],"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:ebf12965380b39889c99a9c02e82ba465f887b45975b6e389d42e9e6a3857888","sha256:0ea33a93585cf1917ba522b2304634c3073654062d5282c1346322967790ef33","sha256:9922bc15eeefe1637b803ef2106f178152ce19a391f24aec838cbe2e48e73303","sha256:dc00fbef458ad3204bbb548e2d766813f593d857b845a940a0de76aed94c94d1","sha256:5cb2a5009179b1e78ecfef81a19756328bb266456cf9a9dbbcf9af8b83b735f0","sha256:9bdb2c849099a99c8ab35f6fd7469c623635e8f4479a0a5a3df61e22bae509f6","sha256:6408527580eade39c2692dbb6b0f6a9321448d06ea1c2eef06bb7f37da9c5013","sha256:83abef706f5ae199af65d1c13d737d0eb36219f0d18e36c6d8ff06159df39a63","sha256:c03283c257abd289a30b4f5e9e1345da0e9bfdc6ca398ee7e8fac6d2c1456227","sha256:2da3602d664dd3f71fae83cbc566d4e80b432c6ee8bb4efd94c8e85122f503d4","sha256:82c59ac8ee582542648e634ca5aff9a464c68ff8a054f105a58689fb52209e34","sha256:2f4a5c9187c249834ebc28783bd3c65bdcbacaa8baa6620ddaa27846dd3ef708","sha256:6ca56f561e677ae06c3bc87a70792642d671a4416becb9a101577c1a6e090e36","sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812","sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079"]}}`),
					FileMode: os.ModePerm,
				},
			},
			apkIndexArchivePath: "testdata/history_v3.9.json",
			expected:            nil,
		},
		"new": {
			targetOS: analyzer.OS{
				Family: "alpine",
				Name:   "3.9.1",
			},
			fileMap: extractor.FileMap{
				"/config": extractor.FileData{
					Body:     []byte(`{"architecture":"amd64","config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","PHPIZE_DEPS=autoconf \t\tdpkg-dev dpkg \t\tfile \t\tg++ \t\tgcc \t\tlibc-dev \t\tmake \t\tpkgconf \t\tre2c","PHP_INI_DIR=/usr/local/etc/php","PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2","PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2","PHP_LDFLAGS=-Wl,-O1 -Wl,--hash-style=both -pie","GPG_KEYS=CBAF69F173A0FEA4B537F470D66C9593118BCCB6 F38252826ACD957EF380D39F2F7956BC5DA04B5D","PHP_VERSION=7.3.5","PHP_URL=https://www.php.net/get/php-7.3.5.tar.xz/from/this/mirror","PHP_ASC_URL=https://www.php.net/get/php-7.3.5.tar.xz.asc/from/this/mirror","PHP_SHA256=e1011838a46fd4a195c8453b333916622d7ff5bce4aca2d9d99afac142db2472","PHP_MD5=","COMPOSER_ALLOW_SUPERUSER=1","COMPOSER_HOME=/tmp","COMPOSER_VERSION=1.7.3"],"Cmd":["composer"],"ArgsEscaped":true,"Image":"sha256:45a1f30c00e614b0d90bb2a24affba0a304ff27660ad4717987fefe067cadec8","Volumes":null,"WorkingDir":"/app","Entrypoint":["/bin/sh","/docker-entrypoint.sh"],"OnBuild":null,"Labels":null},"container":"47d9d33b3d5abb0316dba1a0bfcbc12a6fa88d98ad30170c41d30718003de82e","container_config":{"Hostname":"47d9d33b3d5a","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","PHPIZE_DEPS=autoconf \t\tdpkg-dev dpkg \t\tfile \t\tg++ \t\tgcc \t\tlibc-dev \t\tmake \t\tpkgconf \t\tre2c","PHP_INI_DIR=/usr/local/etc/php","PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2","PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2","PHP_LDFLAGS=-Wl,-O1 -Wl,--hash-style=both -pie","GPG_KEYS=CBAF69F173A0FEA4B537F470D66C9593118BCCB6 F38252826ACD957EF380D39F2F7956BC5DA04B5D","PHP_VERSION=7.3.5","PHP_URL=https://www.php.net/get/php-7.3.5.tar.xz/from/this/mirror","PHP_ASC_URL=https://www.php.net/get/php-7.3.5.tar.xz.asc/from/this/mirror","PHP_SHA256=e1011838a46fd4a195c8453b333916622d7ff5bce4aca2d9d99afac142db2472","PHP_MD5=","COMPOSER_ALLOW_SUPERUSER=1","COMPOSER_HOME=/tmp","COMPOSER_VERSION=1.7.3"],"Cmd":["/bin/sh","-c","#(nop) ","CMD [\"composer\"]"],"ArgsEscaped":true,"Image":"sha256:45a1f30c00e614b0d90bb2a24affba0a304ff27660ad4717987fefe067cadec8","Volumes":null,"WorkingDir":"/app","Entrypoint":["/bin/sh","/docker-entrypoint.sh"],"OnBuild":null,"Labels":{}},"created":"2019-05-11T05:10:20.331457195Z","docker_version":"18.06.1-ce","history":[{"created":"2019-05-11T00:07:03.358250803Z","created_by":"/bin/sh -c #(nop) ADD file:a86aea1f3a7d68f6ae03397b99ea77f2e9ee901c5c59e59f76f93adbb4035913 in / "},{"created":"2019-05-11T00:07:03.510395965Z","created_by":"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]","empty_layer":true},{"created":"2019-05-11T03:04:43.08006936Z","created_by":"/bin/sh -c #(nop)  ENV PHPIZE_DEPS=autoconf \t\tdpkg-dev dpkg \t\tfile \t\tg++ \t\tgcc \t\tlibc-dev \t\tmake \t\tpkgconf \t\tre2c","empty_layer":true},{"created":"2019-05-11T03:04:44.655269947Z","created_by":"/bin/sh -c apk add --no-cache \t\tca-certificates \t\tcurl \t\ttar \t\txz \t\topenssl"},{"created":"2019-05-11T03:04:45.787769041Z","created_by":"/bin/sh -c set -x \t\u0026\u0026 addgroup -g 82 -S www-data \t\u0026\u0026 adduser -u 82 -D -S -G www-data www-data"},{"created":"2019-05-11T03:04:46.047800659Z","created_by":"/bin/sh -c #(nop)  ENV PHP_INI_DIR=/usr/local/etc/php","empty_layer":true},{"created":"2019-05-11T03:04:47.131691293Z","created_by":"/bin/sh -c set -eux; \tmkdir -p \"$PHP_INI_DIR/conf.d\"; \t[ ! -d /var/www/html ]; \tmkdir -p /var/www/html; \tchown www-data:www-data /var/www/html; \tchmod 777 /var/www/html"},{"created":"2019-05-11T03:04:47.360137598Z","created_by":"/bin/sh -c #(nop)  ENV PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2","empty_layer":true},{"created":"2019-05-11T03:04:47.624002469Z","created_by":"/bin/sh -c #(nop)  ENV PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2","empty_layer":true},{"created":"2019-05-11T03:04:47.823552655Z","created_by":"/bin/sh -c #(nop)  ENV PHP_LDFLAGS=-Wl,-O1 -Wl,--hash-style=both -pie","empty_layer":true},{"created":"2019-05-11T03:04:48.090975339Z","created_by":"/bin/sh -c #(nop)  ENV GPG_KEYS=CBAF69F173A0FEA4B537F470D66C9593118BCCB6 F38252826ACD957EF380D39F2F7956BC5DA04B5D","empty_layer":true},{"created":"2019-05-11T03:04:48.311134986Z","created_by":"/bin/sh -c #(nop)  ENV PHP_VERSION=7.3.5","empty_layer":true},{"created":"2019-05-11T03:04:48.546724822Z","created_by":"/bin/sh -c #(nop)  ENV PHP_URL=https://www.php.net/get/php-7.3.5.tar.xz/from/this/mirror PHP_ASC_URL=https://www.php.net/get/php-7.3.5.tar.xz.asc/from/this/mirror","empty_layer":true},{"created":"2019-05-11T03:04:48.787069773Z","created_by":"/bin/sh -c #(nop)  ENV PHP_SHA256=e1011838a46fd4a195c8453b333916622d7ff5bce4aca2d9d99afac142db2472 PHP_MD5=","empty_layer":true},{"created":"2019-05-11T03:04:54.588915046Z","created_by":"/bin/sh -c set -xe; \t\tapk add --no-cache --virtual .fetch-deps \t\tgnupg \t\twget \t; \t\tmkdir -p /usr/src; \tcd /usr/src; \t\twget -O php.tar.xz \"$PHP_URL\"; \t\tif [ -n \"$PHP_SHA256\" ]; then \t\techo \"$PHP_SHA256 *php.tar.xz\" | sha256sum -c -; \tfi; \tif [ -n \"$PHP_MD5\" ]; then \t\techo \"$PHP_MD5 *php.tar.xz\" | md5sum -c -; \tfi; \t\tif [ -n \"$PHP_ASC_URL\" ]; then \t\twget -O php.tar.xz.asc \"$PHP_ASC_URL\"; \t\texport GNUPGHOME=\"$(mktemp -d)\"; \t\tfor key in $GPG_KEYS; do \t\t\tgpg --batch --keyserver ha.pool.sks-keyservers.net --recv-keys \"$key\"; \t\tdone; \t\tgpg --batch --verify php.tar.xz.asc php.tar.xz; \t\tcommand -v gpgconf \u003e /dev/null \u0026\u0026 gpgconf --kill all; \t\trm -rf \"$GNUPGHOME\"; \tfi; \t\tapk del --no-network .fetch-deps"},{"created":"2019-05-11T03:04:54.86888363Z","created_by":"/bin/sh -c #(nop) COPY file:ce57c04b70896f77cc11eb2766417d8a1240fcffe5bba92179ec78c458844110 in /usr/local/bin/ "},{"created":"2019-05-11T03:12:28.585346378Z","created_by":"/bin/sh -c set -xe \t\u0026\u0026 apk add --no-cache --virtual .build-deps \t\t$PHPIZE_DEPS \t\targon2-dev \t\tcoreutils \t\tcurl-dev \t\tlibedit-dev \t\tlibsodium-dev \t\tlibxml2-dev \t\topenssl-dev \t\tsqlite-dev \t\t\u0026\u0026 export CFLAGS=\"$PHP_CFLAGS\" \t\tCPPFLAGS=\"$PHP_CPPFLAGS\" \t\tLDFLAGS=\"$PHP_LDFLAGS\" \t\u0026\u0026 docker-php-source extract \t\u0026\u0026 cd /usr/src/php \t\u0026\u0026 gnuArch=\"$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)\" \t\u0026\u0026 ./configure \t\t--build=\"$gnuArch\" \t\t--with-config-file-path=\"$PHP_INI_DIR\" \t\t--with-config-file-scan-dir=\"$PHP_INI_DIR/conf.d\" \t\t\t\t--enable-option-checking=fatal \t\t\t\t--with-mhash \t\t\t\t--enable-ftp \t\t--enable-mbstring \t\t--enable-mysqlnd \t\t--with-password-argon2 \t\t--with-sodium=shared \t\t\t\t--with-curl \t\t--with-libedit \t\t--with-openssl \t\t--with-zlib \t\t\t\t$(test \"$gnuArch\" = 's390x-linux-gnu' \u0026\u0026 echo '--without-pcre-jit') \t\t\t\t$PHP_EXTRA_CONFIGURE_ARGS \t\u0026\u0026 make -j \"$(nproc)\" \t\u0026\u0026 find -type f -name '*.a' -delete \t\u0026\u0026 make install \t\u0026\u0026 { find /usr/local/bin /usr/local/sbin -type f -perm +0111 -exec strip --strip-all '{}' + || true; } \t\u0026\u0026 make clean \t\t\u0026\u0026 cp -v php.ini-* \"$PHP_INI_DIR/\" \t\t\u0026\u0026 cd / \t\u0026\u0026 docker-php-source delete \t\t\u0026\u0026 runDeps=\"$( \t\tscanelf --needed --nobanner --format '%n#p' --recursive /usr/local \t\t\t| tr ',' '\\n' \t\t\t| sort -u \t\t\t| awk 'system(\"[ -e /usr/local/lib/\" $1 \" ]\") == 0 { next } { print \"so:\" $1 }' \t)\" \t\u0026\u0026 apk add --no-cache $runDeps \t\t\u0026\u0026 apk del --no-network .build-deps \t\t\u0026\u0026 pecl update-channels \t\u0026\u0026 rm -rf /tmp/pear ~/.pearrc"},{"created":"2019-05-11T03:12:29.098563791Z","created_by":"/bin/sh -c #(nop) COPY multi:03970f7b3773444b9f7f244f89d3ceeb4253ac6599f0ba0a4c0306c5bf7d1b9b in /usr/local/bin/ "},{"created":"2019-05-11T03:12:30.099974579Z","created_by":"/bin/sh -c docker-php-ext-enable sodium"},{"created":"2019-05-11T03:12:30.266754534Z","created_by":"/bin/sh -c #(nop)  ENTRYPOINT [\"docker-php-entrypoint\"]","empty_layer":true},{"created":"2019-05-11T03:12:30.414982715Z","created_by":"/bin/sh -c #(nop)  CMD [\"php\" \"-a\"]","empty_layer":true},{"created":"2019-05-11T05:10:12.574223281Z","created_by":"/bin/sh -c apk add --no-cache --virtual .composer-rundeps git subversion openssh mercurial tini bash patch make zip unzip coreutils  \u0026\u0026 apk add --no-cache --virtual .build-deps zlib-dev libzip-dev  \u0026\u0026 docker-php-ext-configure zip --with-libzip  \u0026\u0026 docker-php-ext-install -j$(getconf _NPROCESSORS_ONLN) zip opcache  \u0026\u0026 runDeps=\"$(     scanelf --needed --nobanner --format '%n#p' --recursive /usr/local/lib/php/extensions       | tr ',' '\\n'       | sort -u       | awk 'system(\"[ -e /usr/local/lib/\" $1 \" ]\") == 0 { next } { print \"so:\" $1 }'     )\"  \u0026\u0026 apk add --no-cache --virtual .composer-phpext-rundeps $runDeps  \u0026\u0026 apk del .build-deps  \u0026\u0026 printf \"# composer php cli ini settings\\ndate.timezone=UTC\\nmemory_limit=-1\\nopcache.enable_cli=1\\n\" \u003e $PHP_INI_DIR/php-cli.ini"},{"created":"2019-05-11T05:10:12.831274473Z","created_by":"/bin/sh -c #(nop)  ENV COMPOSER_ALLOW_SUPERUSER=1","empty_layer":true},{"created":"2019-05-11T05:10:13.003330711Z","created_by":"/bin/sh -c #(nop)  ENV COMPOSER_HOME=/tmp","empty_layer":true},{"created":"2019-05-11T05:10:18.503381656Z","created_by":"/bin/sh -c #(nop)  ENV COMPOSER_VERSION=1.7.3","empty_layer":true},{"created":"2019-05-11T05:10:19.619504049Z","created_by":"/bin/sh -c curl --silent --fail --location --retry 3 --output /tmp/installer.php --url https://raw.githubusercontent.com/composer/getcomposer.org/cb19f2aa3aeaa2006c0cd69a7ef011eb31463067/web/installer  \u0026\u0026 php -r \"     \\$signature = '48e3236262b34d30969dca3c37281b3b4bbe3221bda826ac6a9a62d6444cdb0dcd0615698a5cbe587c3f0fe57a54d8f5';     \\$hash = hash('sha384', file_get_contents('/tmp/installer.php'));     if (!hash_equals(\\$signature, \\$hash)) {       unlink('/tmp/installer.php');       echo 'Integrity check failed, installer is either corrupt or worse.' . PHP_EOL;       exit(1);     }\"  \u0026\u0026 php /tmp/installer.php --no-ansi --install-dir=/usr/bin --filename=composer --version=${COMPOSER_VERSION}  \u0026\u0026 composer --ansi --version --no-interaction  \u0026\u0026 rm -f /tmp/installer.php"},{"created":"2019-05-11T05:10:19.803213107Z","created_by":"/bin/sh -c #(nop) COPY file:0bcb2d1c76549e38469db832f5bcfcb4c538b26748a9d4246cc64f35a23280d0 in /docker-entrypoint.sh "},{"created":"2019-05-11T05:10:19.987396089Z","created_by":"/bin/sh -c #(nop) WORKDIR /app"},{"created":"2019-05-11T05:10:20.159217819Z","created_by":"/bin/sh -c #(nop)  ENTRYPOINT [\"/bin/sh\" \"/docker-entrypoint.sh\"]","empty_layer":true},{"created":"2019-05-11T05:10:20.331457195Z","created_by":"/bin/sh -c #(nop)  CMD [\"composer\"]","empty_layer":true}],"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:f1b5933fe4b5f49bbe8258745cf396afe07e625bdab3168e364daf7c956b6b81","sha256:3575e617b5f4845d72ac357ea1712be9037c1f73e8893fa4a5b887be964f8f59","sha256:414e112bbb2c35bef0e76708e87a68b521a011a1941fe6d062e30da800c69d1f","sha256:21f626200b4c7decb2150402d3b801a886ef9dab022d11478eb3240b2a1bb175","sha256:64a9089492da43bf6f8f3b3b45aafee7d71f1dfd6464477e27b43b4dbe1da341","sha256:c60e74b6df1608ee7a080978a9f5eddce48dd4d7366b65a5ec00c6e96deabfae","sha256:489ab25ac6f9d77b5868493bfccc72bcbfaa85d8f393cdd21f3a6cb6e0256c15","sha256:5a8c7d3402d369f0f5838b74da5c2bd3eaa64c6bbd8d8e11d7ec0affb074c276","sha256:fe6bde799f85946dbed35f5f614532d68a9f8b62f3f42ae9164740c3d0a6296a","sha256:40dd29f574f814717669b34efc4ae527a3af0829a2cccb9ec4f077a8cb2766cc","sha256:0d5d3c0e6691d3c6d24dc782de33d64d490226c503414da0df93b8f605f93da5","sha256:41467c77644ee108b8ef3e89db7f235ebb720ed4a4041bf746d7342193e6bc7d","sha256:6a64ec219cdeecfe63aac5b7f43fb3cb6651c6b1a02ebbde6deeabf8a7e3b345"]}}`),
					FileMode: os.ModePerm,
				},
			},
			apkIndexArchivePath: "testdata/history_v3.9.json",
			expected: []analyzer.Package{
				{Name: "acl", Version: "2.2.52-r5"},
				{Name: "apr", Version: "1.6.5-r0"},
				{Name: "apr-util", Version: "1.6.1-r5"},
				{Name: "argon2", Version: "20171227-r1"},
				{Name: "argon2-dev", Version: "20171227-r1"},
				{Name: "argon2-libs", Version: "20171227-r1"},
				{Name: "attr", Version: "2.4.47-r7"},
				{Name: "autoconf", Version: "2.69-r2"},
				{Name: "bash", Version: "4.4.19-r1"},
				{Name: "binutils", Version: "2.31.1-r2"},
				{Name: "busybox", Version: "1.29.3-r10"},
				{Name: "bzip2", Version: "1.0.6-r6"},
				{Name: "ca-certificates", Version: "20190108-r0"},
				{Name: "coreutils", Version: "8.30-r0"},
				{Name: "curl", Version: "7.64.0-r1"},
				{Name: "curl-dev", Version: "7.64.0-r1"},
				{Name: "cyrus-sasl", Version: "2.1.27-r1"},
				{Name: "db", Version: "5.3.28-r1"},
				{Name: "dpkg", Version: "1.19.2-r0"},
				{Name: "dpkg-dev", Version: "1.19.2-r0"},
				{Name: "expat", Version: "2.2.6-r0"},
				{Name: "file", Version: "5.36-r0"},
				{Name: "g++", Version: "8.3.0-r0"},
				{Name: "gcc", Version: "8.3.0-r0"},
				{Name: "gdbm", Version: "1.13-r1"},
				{Name: "git", Version: "2.20.1-r0"},
				{Name: "gmp", Version: "6.1.2-r1"},
				{Name: "gnupg", Version: "2.2.12-r0"},
				{Name: "gnutls", Version: "3.6.7-r0"},
				{Name: "isl", Version: "0.18-r0"},
				{Name: "libacl", Version: "2.2.52-r5"},
				{Name: "libassuan", Version: "2.5.1-r0"},
				{Name: "libatomic", Version: "8.3.0-r0"},
				{Name: "libattr", Version: "2.4.47-r7"},
				{Name: "libbz2", Version: "1.0.6-r6"},
				{Name: "libc-dev", Version: "0.7.1-r0"},
				{Name: "libcap", Version: "2.26-r0"},
				{Name: "libcrypto1.1", Version: "1.1.1b-r1"},
				{Name: "libcurl", Version: "7.64.0-r1"},
				{Name: "libedit", Version: "20181209.3.1-r0"},
				{Name: "libedit-dev", Version: "20181209.3.1-r0"},
				{Name: "libffi", Version: "3.2.1-r6"},
				{Name: "libgcc", Version: "8.3.0-r0"},
				{Name: "libgcrypt", Version: "1.8.4-r0"},
				{Name: "libgomp", Version: "8.3.0-r0"},
				{Name: "libgpg-error", Version: "1.33-r0"},
				{Name: "libksba", Version: "1.3.5-r0"},
				{Name: "libldap", Version: "2.4.47-r2"},
				{Name: "libmagic", Version: "5.36-r0"},
				{Name: "libsasl", Version: "2.1.27-r1"},
				{Name: "libsodium", Version: "1.0.16-r0"},
				{Name: "libsodium-dev", Version: "1.0.16-r0"},
				{Name: "libssh2", Version: "1.8.2-r0"},
				{Name: "libssh2-dev", Version: "1.8.2-r0"},
				{Name: "libssl1.1", Version: "1.1.1b-r1"},
				{Name: "libstdc++", Version: "8.3.0-r0"},
				{Name: "libtasn1", Version: "4.13-r0"},
				{Name: "libunistring", Version: "0.9.10-r0"},
				{Name: "libuuid", Version: "2.33-r0"},
				{Name: "libxml2", Version: "2.9.9-r1"},
				{Name: "libxml2-dev", Version: "2.9.9-r1"},
				{Name: "lz4", Version: "1.8.3-r2"},
				{Name: "lz4-libs", Version: "1.8.3-r2"},
				{Name: "m4", Version: "1.4.18-r1"},
				{Name: "make", Version: "4.2.1-r2"},
				{Name: "mercurial", Version: "4.9.1-r0"},
				{Name: "mpc1", Version: "1.0.3-r1"},
				{Name: "mpfr3", Version: "3.1.5-r1"},
				{Name: "musl", Version: "1.1.20-r4"},
				{Name: "musl-dev", Version: "1.1.20-r4"},
				{Name: "ncurses", Version: "6.1_p20190105-r0"},
				{Name: "ncurses-dev", Version: "6.1_p20190105-r0"},
				{Name: "ncurses-libs", Version: "6.1_p20190105-r0"},
				{Name: "ncurses-terminfo", Version: "6.1_p20190105-r0"},
				{Name: "ncurses-terminfo-base", Version: "6.1_p20190105-r0"},
				{Name: "nettle", Version: "3.4.1-r0"},
				{Name: "nghttp2", Version: "1.35.1-r0"},
				{Name: "nghttp2-dev", Version: "1.35.1-r0"},
				{Name: "nghttp2-libs", Version: "1.35.1-r0"},
				{Name: "npth", Version: "1.6-r0"},
				{Name: "openldap", Version: "2.4.47-r2"},
				{Name: "openssh", Version: "7.9_p1-r5"},
				{Name: "openssh-client", Version: "7.9_p1-r5"},
				{Name: "openssh-keygen", Version: "7.9_p1-r5"},
				{Name: "openssh-server", Version: "7.9_p1-r5"},
				{Name: "openssh-server-common", Version: "7.9_p1-r5"},
				{Name: "openssh-sftp-server", Version: "7.9_p1-r5"},
				{Name: "openssl", Version: "1.1.1b-r1"},
				{Name: "openssl-dev", Version: "1.1.1b-r1"},
				{Name: "p11-kit", Version: "0.23.14-r0"},
				{Name: "patch", Version: "2.7.6-r4"},
				{Name: "pcre2", Version: "10.32-r1"},
				{Name: "perl", Version: "5.26.3-r0"},
				{Name: "pinentry", Version: "1.1.0-r0"},
				{Name: "pkgconf", Version: "1.6.0-r0"},
				{Name: "python2", Version: "2.7.16-r1"},
				{Name: "re2c", Version: "1.1.1-r0"},
				{Name: "readline", Version: "7.0.003-r1"},
				{Name: "serf", Version: "1.3.9-r5"},
				{Name: "sqlite", Version: "3.26.0-r3"},
				{Name: "sqlite-dev", Version: "3.26.0-r3"},
				{Name: "sqlite-libs", Version: "3.26.0-r3"},
				{Name: "subversion", Version: "1.11.1-r0"},
				{Name: "subversion-libs", Version: "1.11.1-r0"},
				{Name: "tar", Version: "1.32-r0"},
				{Name: "unzip", Version: "6.0-r4"},
				{Name: "util-linux", Version: "2.33-r0"},
				{Name: "wget", Version: "1.20.3-r0"},
				{Name: "xz", Version: "5.2.4-r0"},
				{Name: "xz-libs", Version: "5.2.4-r0"},
				{Name: "zip", Version: "3.0-r7"},
				{Name: "zlib", Version: "1.2.11-r1"},
				{Name: "zlib-dev", Version: "1.2.11-r1"},
			},
		},
	}
	analyzer := alpineCmdAnalyzer{}
	for testName, v := range tests {
		f, err := os.Open(v.apkIndexArchivePath)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		apkIndexArchive = &apkIndex{}
		if err = json.NewDecoder(f).Decode(apkIndexArchive); err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		actual, _ := analyzer.Analyze(v.targetOS, v.fileMap)
		sort.Slice(actual, func(i, j int) bool {
			return actual[i].Name < actual[j].Name
		})
		if !reflect.DeepEqual(v.expected, actual) {
			t.Errorf("[%s]\n%s", testName, pretty.Compare(v.expected, actual))
		}
	}
}

func TestParseCommand(t *testing.T) {
	var tests = map[string]struct {
		command  string
		envs     map[string]string
		expected []string
	}{
		"no package": {
			command:  "/bin/sh -c #(nop) ADD file:49f9e47e678d868d5b023482aa8dded71276a241a665c4f8b55ca77269321b34 in / ",
			envs:     nil,
			expected: nil,
		},
		"no-cache": {
			command:  "/bin/sh -c apk add --no-cache --virtual .persistent-deps \t\tca-certificates \t\tcurl \t\ttar \t\txz \t\tlibressl",
			envs:     nil,
			expected: []string{"ca-certificates", "curl", "tar", "xz", "libressl"},
		},
		// TODO: support $runDeps
		"joined by &&": {
			command:  `/bin/sh -c apk add --no-cache --virtual .build-deps zlib-dev  && docker-php-ext-install zip  && runDeps=\"$(     scanelf --needed --nobanner --format '%n#p' --recursive /usr/local/lib/php/extensions     | tr ',' '\\n'     | sort -u     | awk 'system(\"[ -e /usr/local/lib/\" $1 \" ]\") == 0 { next } { print \"so:\" $1 }'     )\"  && apk add --virtual .composer-phpext-rundeps $runDeps  && apk del .build-deps`,
			envs:     nil,
			expected: []string{"zlib-dev"},
		},
		"joined by ;": {
			command:  "/bin/sh -c set -xe; \t\tapk add --no-cache --virtual .fetch-deps \t\tgnupg \t\twget \t; \t\tmkdir -p /usr/src; \tcd /usr/src; \t\twget -O php.tar.xz \"$PHP_URL\"; \t\tif [ -n \"$PHP_SHA256\" ]; then \t\techo \"$PHP_SHA256 *php.tar.xz\" | sha256sum -c -; \tfi; \tif [ -n \"$PHP_MD5\" ]; then \t\techo \"$PHP_MD5 *php.tar.xz\" | md5sum -c -; \tfi; \t\tif [ -n \"$PHP_ASC_URL\" ]; then \t\twget -O php.tar.xz.asc \"$PHP_ASC_URL\"; \t\texport GNUPGHOME=\"$(mktemp -d)\"; \t\tfor key in $GPG_KEYS; do \t\t\tgpg --keyserver ha.pool.sks-keyservers.net --recv-keys \"$key\"; \t\tdone; \t\tgpg --batch --verify php.tar.xz.asc php.tar.xz; \t\tcommand -v gpgconf > /dev/null && gpgconf --kill all; \t\trm -rf \"$GNUPGHOME\"; \tfi; \t\tapk del .fetch-deps",
			envs:     nil,
			expected: []string{"gnupg", "wget"},
		},
		"ENV": {
			command: "/bin/sh -c set -xe \t&& apk add --no-cache --virtual .build-deps \t\t$PHPIZE_DEPS \t\tcoreutils \t\tcurl-dev \t\tlibedit-dev \t\tlibressl-dev \t\tlibsodium-dev \t\tlibxml2-dev \t\tsqlite-dev",
			envs: map[string]string{
				"$PHPIZE_DEPS": "autoconf \t\tdpkg-dev dpkg \t\tfile \t\tg++ \t\tgcc \t\tlibc-dev \t\tmake \t\tpkgconf \t\tre2c",
			},
			expected: []string{
				"autoconf",
				"dpkg-dev",
				"dpkg",
				"file",
				"g++",
				"gcc",
				"libc-dev",
				"make",
				"pkgconf",
				"re2c",
				"coreutils",
				"curl-dev",
				"libedit-dev",
				"libressl-dev",
				"libsodium-dev",
				"libxml2-dev",
				"sqlite-dev",
			},
		},
	}
	analyzer := alpineCmdAnalyzer{}
	for testName, v := range tests {
		actual := analyzer.parseCommand(v.command, v.envs)
		if !reflect.DeepEqual(v.expected, actual) {
			t.Errorf("[%s]\n%s", testName, pretty.Compare(v.expected, actual))
		}
	}
}

func TestResolveDependency(t *testing.T) {
	var tests = map[string]struct {
		pkgName             string
		apkIndexArchivePath string
		expected            map[string]struct{}
	}{
		"low": {
			pkgName:             "libblkid",
			apkIndexArchivePath: "testdata/history_v3.9.json",
			expected: map[string]struct{}{
				"libblkid": {},
				"libuuid":  {},
				"musl":     {},
			},
		},
		"medium": {
			pkgName:             "libgcab",
			apkIndexArchivePath: "testdata/history_v3.9.json",
			expected: map[string]struct{}{
				"busybox":  {},
				"libblkid": {},
				"libuuid":  {},
				"musl":     {},
				"libmount": {},
				"pcre":     {},
				"glib":     {},
				"libgcab":  {},
				"libintl":  {},
				"zlib":     {},
				"libffi":   {},
			},
		},
		"high": {
			pkgName:             "postgresql",
			apkIndexArchivePath: "testdata/history_v3.9.json",
			expected: map[string]struct{}{
				"busybox":               {},
				"ncurses-terminfo-base": {},
				"ncurses-terminfo":      {},
				"libedit":               {},
				"db":                    {},
				"libsasl":               {},
				"libldap":               {},
				"libpq":                 {},
				"postgresql-client":     {},
				"tzdata":                {},
				"libxml2":               {},
				"postgresql":            {},
				"musl":                  {},
				"libcrypto1.1":          {},
				"libssl1.1":             {},
				"ncurses-libs":          {},
				"zlib":                  {},
			},
		},
		"package alias": {
			pkgName:             "sqlite-dev",
			apkIndexArchivePath: "testdata/history_v3.9.json",
			expected: map[string]struct{}{
				"sqlite-dev":  {},
				"sqlite-libs": {},
				"pkgconf":     {}, // pkgconfig => pkgconf
				"musl":        {},
			},
		},
	}
	analyzer := alpineCmdAnalyzer{}
	for testName, v := range tests {
		f, err := os.Open(v.apkIndexArchivePath)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if err = json.NewDecoder(f).Decode(&apkIndexArchive); err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		pkgs := analyzer.resolveDependency(v.pkgName)
		actual := map[string]struct{}{}
		for _, pkg := range pkgs {
			actual[pkg] = struct{}{}
		}
		if !reflect.DeepEqual(v.expected, actual) {
			t.Errorf("[%s]\n%s", testName, pretty.Compare(v.expected, actual))
		}
	}
}

func TestGuessVersion(t *testing.T) {
	var tests = map[string]struct {
		apkIndexArchive *apkIndex
		pkgs            []string
		createdAt       time.Time
		expected        []analyzer.Package
	}{
		"normal": {
			apkIndexArchive: &apkIndex{
				Package: map[string]archive{
					"busybox": {
						Versions: map[string]int{
							"1.24.2-r0": 100,
							"1.24.2-r1": 200,
							"1.24.2-r2": 300,
						},
					},
				},
			},
			pkgs:      []string{"busybox"},
			createdAt: time.Unix(200, 0),
			expected: []analyzer.Package{
				{
					Name:    "busybox",
					Version: "1.24.2-r1",
				},
			},
		},
		"unmatched version": {
			apkIndexArchive: &apkIndex{
				Package: map[string]archive{
					"busybox": {
						Versions: map[string]int{
							"1.24.2-r0": 100,
							"1.24.2-r1": 200,
							"1.24.2-r2": 300,
						},
					},
				},
			},
			pkgs:      []string{"busybox"},
			createdAt: time.Unix(50, 0),
			expected:  nil,
		},
		"unmatched package": {
			apkIndexArchive: &apkIndex{
				Package: map[string]archive{
					"busybox": {
						Versions: map[string]int{
							"1.24.2-r0": 100,
							"1.24.2-r1": 200,
							"1.24.2-r2": 300,
						},
					},
				},
			},
			pkgs:      []string{"busybox", "openssl"},
			createdAt: time.Unix(200, 0),
			expected: []analyzer.Package{
				{
					Name:    "busybox",
					Version: "1.24.2-r1",
				},
			},
		},
		"origin": {
			apkIndexArchive: &apkIndex{
				Package: map[string]archive{
					"sqlite-dev": {
						Versions: map[string]int{
							"3.26.0-r0": 100,
							"3.26.0-r1": 200,
							"3.26.0-r2": 300,
							"3.26.0-r3": 400,
						},
						Origin: "sqlite",
					},
				},
			},
			pkgs:      []string{"sqlite-dev"},
			createdAt: time.Unix(500, 0),
			expected: []analyzer.Package{
				{
					Name:    "sqlite-dev",
					Version: "3.26.0-r3",
				},
				{
					Name:    "sqlite",
					Version: "3.26.0-r3",
				},
			},
		},
	}
	analyzer := alpineCmdAnalyzer{}
	for testName, v := range tests {
		apkIndexArchive = v.apkIndexArchive
		actual := analyzer.guessVersion(v.pkgs, v.createdAt)
		if !reflect.DeepEqual(v.expected, actual) {
			t.Errorf("[%s]\n%s", testName, pretty.Compare(v.expected, actual))
		}
	}
}
