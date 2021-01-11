module github.com/aquasecurity/fanal

go 1.13

require (
	github.com/GoogleCloudPlatform/docker-credential-gcr v1.5.0
	github.com/Microsoft/go-winio v0.4.16 // indirect
	github.com/Microsoft/hcsshim v0.8.14 // indirect
	github.com/alicebob/miniredis/v2 v2.14.1
	github.com/aquasecurity/go-dep-parser v0.0.0-20201028043324-889d4a92b8e0
	github.com/aquasecurity/testdocker v0.0.0-20201220111429-5278b43e3eba
	github.com/aws/aws-sdk-go v1.31.6
	github.com/containerd/containerd v1.4.3 // indirect
	github.com/containerd/continuity v0.0.0-20201208142359-180525291bb7 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/cli v20.10.0-beta1.0.20201029214301-1d20b15adc38+incompatible // indirect
	github.com/docker/docker v17.12.0-ce-rc1.0.20200916142827-bd33bbf0497b+incompatible
	github.com/docker/go-connections v0.4.0
	github.com/go-git/go-git/v5 v5.0.0
	github.com/go-redis/redis/v8 v8.4.0
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.4.3 // indirect
	github.com/google/go-containerregistry v0.1.2
	github.com/google/uuid v1.1.4 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/hashicorp/go-multierror v1.1.0
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/knqyf263/go-rpmdb v0.0.0-20201215100354-a9e3110d8ee1
	github.com/knqyf263/nested v0.0.1
	github.com/kylelemons/godebug v0.0.0-20170820004349-d65d576e9348
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.2-0.20190823105129-775207bd45b6
	github.com/opencontainers/runc v1.0.0-rc92 // indirect
	github.com/saracen/walker v0.0.0-20191201085201-324a081bae7e
	github.com/sirupsen/logrus v1.7.0 // indirect
	github.com/sosedoff/gitkit v0.2.0
	github.com/stretchr/testify v1.6.1
	github.com/testcontainers/testcontainers-go v0.9.0
	github.com/urfave/cli/v2 v2.2.0
	go.etcd.io/bbolt v1.3.5
	golang.org/x/crypto v0.0.0-20201117144127-c1f2f97bffc9 // indirect
	golang.org/x/net v0.0.0-20201224014010-6772e930b67b // indirect
	golang.org/x/sync v0.0.0-20201207232520-09787c993a3a // indirect
	golang.org/x/sys v0.0.0-20210110051926-789bb1bd4061 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
	google.golang.org/genproto v0.0.0-20210108203827-ffc7fda8c3d7 // indirect
	google.golang.org/grpc v1.34.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gotest.tools/v3 v3.0.2 // indirect
)

// https://github.com/moby/term/issues/15
replace golang.org/x/sys => golang.org/x/sys v0.0.0-20200826173525-f9321e4c35a6
