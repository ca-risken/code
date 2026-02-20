module github.com/ca-risken/code

go 1.24.0

toolchain go1.24.2

// patch https://github.com/ca-risken/go-git/pull/1
replace github.com/go-git/go-git/v5 v5.4.3-0.20220529141257-bc1f419cebcf => github.com/ca-risken/go-git/v5 v5.4.3-0.20220715100214-652d3d7d4a0e

// Ensure compatibility with Go 1.23 toolchains by pinning x/sys before go1.24 build tags
replace golang.org/x/sys => golang.org/x/sys v0.27.0

// Pin unstable OpenTelemetry collector modules required by dd-trace-go tests
replace go.opentelemetry.io/collector/pdata => go.opentelemetry.io/collector/pdata v1.31.0

replace go.opentelemetry.io/collector/pdata/pprofile => go.opentelemetry.io/collector/pdata/pprofile v0.125.0

replace go.opentelemetry.io/collector/pdata/testdata => go.opentelemetry.io/collector/pdata/testdata v0.125.0

require (
	github.com/aquasecurity/trivy v0.30.4
	github.com/aquasecurity/trivy-db v0.0.0-20220801073337-2c0339bb9085
	github.com/aws/aws-sdk-go-v2 v1.39.6
	github.com/aws/aws-sdk-go-v2/service/sqs v1.42.15
	github.com/ca-risken/common/pkg/logging v0.0.0-20251104095036-403011f05377
	github.com/ca-risken/common/pkg/profiler v0.0.0-20251104095036-403011f05377
	github.com/ca-risken/common/pkg/sqs v0.0.0-20221119073224-9db027bda6f8
	github.com/ca-risken/common/pkg/tracer v0.0.0-20251104095036-403011f05377
	github.com/ca-risken/core v0.16.0
	github.com/ca-risken/datasource-api v0.16.1-0.20260220012639-3a8f1da0d63c
	github.com/ca-risken/go-sqs-poller/worker/v5 v5.0.0-20220525093235-9148d33b6aee
	github.com/ca-risken/vulnerability v0.0.0-20250207144506-e2bcae88c3dc
	github.com/cenkalti/backoff/v4 v4.3.0
	github.com/gassara-kys/envconfig v1.4.4
	github.com/go-git/go-git/v5 v5.16.3
	github.com/google/go-cmp v0.7.0
	github.com/google/go-github/v44 v44.1.0
	github.com/spf13/viper v1.13.0
	github.com/stretchr/testify v1.11.1
	github.com/zricethezav/gitleaks/v8 v8.8.6
	golang.org/x/oauth2 v0.33.0
	google.golang.org/grpc v1.77.0
	google.golang.org/protobuf v1.36.10
	k8s.io/utils v0.0.0-20241210054802-24370beab758
)

require (
	dario.cat/mergo v1.0.0 // indirect
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/DATA-DOG/go-sqlmock v1.5.0 // indirect
	github.com/DataDog/datadog-agent/comp/core/tagger/origindetection v0.72.2 // indirect
	github.com/DataDog/datadog-agent/pkg/obfuscate v0.72.2 // indirect
	github.com/DataDog/datadog-agent/pkg/opentelemetry-mapping-go/otlp/attributes v0.72.2 // indirect
	github.com/DataDog/datadog-agent/pkg/proto v0.72.2 // indirect
	github.com/DataDog/datadog-agent/pkg/remoteconfig/state v0.74.0-devel // indirect
	github.com/DataDog/datadog-agent/pkg/trace v0.72.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/log v0.72.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/scrubber v0.72.2 // indirect
	github.com/DataDog/datadog-agent/pkg/version v0.72.2 // indirect
	github.com/DataDog/datadog-go/v5 v5.8.1 // indirect
	github.com/DataDog/dd-trace-go/contrib/database/sql/v2 v2.4.0 // indirect
	github.com/DataDog/dd-trace-go/contrib/gorm.io/gorm.v1/v2 v2.4.0 // indirect
	github.com/DataDog/dd-trace-go/v2 v2.4.0 // indirect
	github.com/DataDog/go-libddwaf/v4 v4.7.0 // indirect
	github.com/DataDog/go-runtime-metrics-internal v0.0.4-0.20250721125240-fdf1ef85b633 // indirect
	github.com/DataDog/go-sqllexer v0.1.9 // indirect
	github.com/DataDog/go-tuf v1.1.1-0.5.2 // indirect
	github.com/DataDog/gostackparse v0.7.0 // indirect
	github.com/DataDog/sketches-go v1.4.7 // indirect
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/ProtonMail/go-crypto v1.1.6 // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.31.20 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.18.24 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.13 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.13 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.13 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.40.2 // indirect
	github.com/aws/smithy-go v1.23.2 // indirect
	github.com/ca-risken/common/pkg/database v0.0.0-20251104095036-403011f05377 // indirect
	github.com/caarlos0/env/v6 v6.10.1 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cihub/seelog v0.0.0-20170130134532-f561c5e57575 // indirect
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/coocood/freecache v1.2.4 // indirect
	github.com/cyphar/filepath-securejoin v0.4.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/ebitengine/purego v0.9.1 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.2.1 // indirect
	github.com/fatih/semgroup v1.2.0 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/gitleaks/go-gitdiff v0.7.6 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.6.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-ozzo/ozzo-validation v3.6.0+incompatible // indirect
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0 // indirect
	github.com/go-sql-driver/mysql v1.9.3 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-containerregistry v0.12.0 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/pprof v0.0.0-20251114195745-4902fdda35c8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/h2non/filetype v1.1.3 // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/hashicorp/hcl v1.0.1-vault-5 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/klauspost/compress v1.18.1 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20251013123823-9fd1530e3ec3 // indirect
	github.com/magiconair/properties v1.8.6 // indirect
	github.com/minio/simdjson-go v0.4.5 // indirect
	github.com/mitchellh/mapstructure v1.5.1-0.20231216201459-8508981c8b6c // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/openai/openai-go v1.8.3 // indirect
	github.com/outcaste-io/ristretto v0.2.3 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pelletier/go-toml/v2 v2.2.2 // indirect
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20211021192214-5ab2d9280aa9 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/pjbgf/sha1cd v0.3.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/puzpuzpuz/xsync/v3 v3.5.1 // indirect
	github.com/richardartoul/molecule v1.0.1-0.20240531184615-7ca0df43c0b3 // indirect
	github.com/rs/zerolog v1.26.1 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.9.1 // indirect
	github.com/sergi/go-diff v1.3.2-0.20230802210424-5b0b94c5c0d3 // indirect
	github.com/shirou/gopsutil/v4 v4.25.10 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/skeema/knownhosts v1.3.1 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/spf13/afero v1.10.0 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/subosito/gotenv v1.4.1 // indirect
	github.com/theckman/httpforwarded v0.4.0 // indirect
	github.com/tidwall/gjson v1.16.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/tinylib/msgp v1.5.0 // indirect
	github.com/tklauser/go-sysconf v0.3.16 // indirect
	github.com/tklauser/numcpus v0.11.0 // indirect
	github.com/vikyd/zero v0.0.0-20190921142904-0f738d0bc858 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.opentelemetry.io/collector/component v1.46.0 // indirect
	go.opentelemetry.io/collector/pdata v1.46.0 // indirect
	go.opentelemetry.io/otel v1.38.0 // indirect
	go.opentelemetry.io/otel/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/crypto v0.44.0 // indirect
	golang.org/x/exp v0.0.0-20251113190631-e25ba8c21ef6 // indirect
	golang.org/x/mod v0.30.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sync v0.18.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251111163417-95abcf5c77ba // indirect
	gopkg.in/DataDog/dd-trace-go.v1 v1.74.8 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gorm.io/driver/mysql v1.6.0 // indirect
	gorm.io/gorm v1.31.1 // indirect
)
