module github.com/ca-risken/code/src/gitleaks

go 1.18

// patch https://github.com/ca-risken/go-git/pull/1
replace github.com/go-git/go-git/v5 v5.4.3-0.20220529141257-bc1f419cebcf => github.com/ca-risken/go-git/v5 v5.4.3-0.20220715100214-652d3d7d4a0e

require (
	github.com/aws/aws-sdk-go-v2 v1.17.1
	github.com/aws/aws-sdk-go-v2/service/sqs v1.19.14
	github.com/ca-risken/common/pkg/logging v0.0.0-20221117060041-4f5403c49c56
	github.com/ca-risken/common/pkg/profiler v0.0.0-20221115050041-1674ac829fe2
	github.com/ca-risken/common/pkg/sqs v0.0.0-20221117060041-4f5403c49c56
	github.com/ca-risken/common/pkg/tracer v0.0.0-20221115050041-1674ac829fe2
	github.com/ca-risken/core v0.4.2-0.20221114035311-c4b88fcc3162
	github.com/ca-risken/datasource-api v0.4.2-0.20221117004341-8eb8754d620e
	github.com/ca-risken/go-sqs-poller/worker/v5 v5.0.0-20220525093235-9148d33b6aee
	github.com/gassara-kys/envconfig v1.4.4
	github.com/go-git/go-git/v5 v5.4.3-0.20220529141257-bc1f419cebcf
	github.com/google/go-github/v44 v44.1.0
	// Gitleaks scanning may fleeze when v1.2.0, so don't udpdate this module
	// github.com/sergi/go-diff v1.1.0 // indirect
	github.com/shurcooL/githubv4 v0.0.0-20210725200734-83ba7b4c9228
	github.com/spf13/viper v1.8.1
	github.com/zricethezav/gitleaks/v8 v8.8.6
	golang.org/x/oauth2 v0.0.0-20210819190943-2bc19b11175f
	google.golang.org/grpc v1.50.1
)

require github.com/stretchr/testify v1.7.1

require (
	github.com/DataDog/datadog-agent/pkg/obfuscate v0.40.1 // indirect
	github.com/DataDog/datadog-go/v5 v5.1.1 // indirect
	github.com/DataDog/gostackparse v0.6.0 // indirect
	github.com/DataDog/sketches-go v1.4.1 // indirect
	github.com/Microsoft/go-winio v0.6.0 // indirect
	github.com/ProtonMail/go-crypto v0.0.0-20210428141323-04723f9f07d7 // indirect
	github.com/acomagu/bufpipe v1.0.3 // indirect
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/aws/aws-sdk-go-v2/config v1.18.1 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.13.1 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.12.19 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.25 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.19 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.26 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.11.25 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.13.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.17.3 // indirect
	github.com/aws/smithy-go v1.13.4 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgraph-io/ristretto v0.1.1 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/emirpasic/gods v1.12.0 // indirect
	github.com/fatih/semgroup v1.2.0 // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/gitleaks/go-gitdiff v0.7.6 // indirect
	github.com/go-git/gcfg v1.5.0 // indirect
	github.com/go-git/go-billy/v5 v5.3.1 // indirect
	github.com/go-ozzo/ozzo-validation v3.6.0+incompatible // indirect
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0 // indirect
	github.com/golang/glog v1.0.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/pprof v0.0.0-20221112000123-84eb7ad69597 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/h2non/filetype v1.1.3 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/kevinburke/ssh_config v1.1.0 // indirect
	github.com/magiconair/properties v1.8.5 // indirect
	github.com/mitchellh/mapstructure v1.4.2 // indirect
	github.com/pelletier/go-toml v1.9.3 // indirect
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20211021192214-5ab2d9280aa9 // indirect
	github.com/philhofer/fwd v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rs/zerolog v1.26.1 // indirect
	github.com/sergi/go-diff v1.1.0 // indirect
	github.com/shurcooL/graphql v0.0.0-20200928012149-18c5c3165e3a // indirect
	github.com/sirupsen/logrus v1.9.0 // indirect
	github.com/smartystreets/assertions v1.0.1 // indirect
	github.com/spf13/afero v1.9.2 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.3.0 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	github.com/tinylib/msgp v1.1.6 // indirect
	github.com/xanzy/ssh-agent v0.3.1 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go4.org/intern v0.0.0-20220617035311-6925f38cc365 // indirect
	go4.org/unsafe/assume-no-moving-gc v0.0.0-20220617031537-928513b29760 // indirect
	golang.org/x/crypto v0.1.0 // indirect
	golang.org/x/mod v0.7.0 // indirect
	golang.org/x/net v0.2.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.2.0 // indirect
	golang.org/x/text v0.4.0 // indirect
	golang.org/x/time v0.2.0 // indirect
	golang.org/x/tools v0.3.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20221116193143-41c2ba794472 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/DataDog/dd-trace-go.v1 v1.43.1 // indirect
	gopkg.in/ini.v1 v1.62.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	inet.af/netaddr v0.0.0-20220811202034-502d2d690317 // indirect
)
