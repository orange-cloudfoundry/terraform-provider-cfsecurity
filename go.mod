module github.com/orange-cloudfoundry/terraform-provider-cfsecurity

go 1.21

// replace github.com/codahale/hdrhistogram => github.com/HdrHistogram/hdrhistogram-go v0.0.0-20210305173142-35c7773a578a
replace github.com/imdario/mergo => dario.cat/mergo v0.3.16

//	github.com/sabhiram/go-gitignore v0.0.0-20210923224102-525f6e181f06
exclude (
	github.com/sabhiram/go-gitignore v0.0.0-20210923224102-525f6e181f06
	github.com/vito/go-interact v1.0.1
)

require (
	code.cloudfoundry.org/cli v7.1.0+incompatible
	github.com/cloudfoundry-community/go-cf-clients-helper/v2 v2.5.1
	github.com/hashicorp/go-uuid v1.0.3
	github.com/hashicorp/terraform-plugin-framework v1.6.1
	github.com/orange-cloudfoundry/cf-security-entitlement v0.88.0
	github.com/prometheus/common v0.49.0
	github.com/thoas/go-funk v0.9.3
)

require (
	code.cloudfoundry.org/bytefmt v0.0.0-20231017140541-3b893ed0421b // indirect
	code.cloudfoundry.org/cfnetworking-cli-api v0.0.0-20190103195135-4b04f26287a6 // indirect
	code.cloudfoundry.org/go-loggregator v7.4.0+incompatible // indirect
	code.cloudfoundry.org/gofileutils v0.0.0-20170111115228-4d0c80011a0f // indirect
	code.cloudfoundry.org/jsonry v1.1.4 // indirect
	code.cloudfoundry.org/tlsconfig v0.0.0-20240116140718-a2c58c2ff70c // indirect
	github.com/SermoDigital/jose v0.9.2-0.20161205224733-f6df55f235c2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver v3.5.1+incompatible // indirect
	github.com/bmatcuk/doublestar v1.3.4 // indirect
	github.com/bmizerany/pat v0.0.0-20210406213842-e4b6760bdd6f // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/charlievieth/fs v0.0.3 // indirect
	github.com/cloudfoundry/bosh-cli v6.4.1+incompatible // indirect
	github.com/cloudfoundry/bosh-utils v0.0.427 // indirect
	github.com/cppforlife/go-patch v0.2.0 // indirect
	github.com/fatih/color v1.16.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.19.1 // indirect
	github.com/hashicorp/go-hclog v1.6.2 // indirect
	github.com/hashicorp/go-plugin v1.6.0 // indirect
	github.com/hashicorp/terraform-plugin-go v0.22.0 // indirect
	github.com/hashicorp/terraform-plugin-log v0.9.0 // indirect
	github.com/hashicorp/terraform-registry-address v0.2.3 // indirect
	github.com/hashicorp/terraform-svchost v0.1.1 // indirect
	github.com/hashicorp/yamux v0.1.1 // indirect
	github.com/jessevdk/go-flags v1.5.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/mitchellh/go-testing-interface v1.14.1 // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_golang v1.19.0 // indirect
	github.com/prometheus/client_model v0.6.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/rivo/uniseg v0.4.6 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/tedsuo/rata v1.0.1-0.20170830210128-07d200713958 // indirect
	github.com/vmihailenco/msgpack/v5 v5.4.1 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	golang.org/x/crypto v0.19.0 // indirect
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
	golang.org/x/term v0.17.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto v0.0.0-20240125205218-1f4bbc51befe // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240125205218-1f4bbc51befe // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240125205218-1f4bbc51befe // indirect
	google.golang.org/grpc v1.61.1 // indirect
	google.golang.org/protobuf v1.32.0 // indirect
	gopkg.in/cheggaaa/pb.v1 v1.0.28 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
