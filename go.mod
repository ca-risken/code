module github.com/ca-risken/code

go 1.21.3

// patch https://github.com/ca-risken/go-git/pull/1
replace github.com/go-git/go-git/v5 v5.4.3-0.20220529141257-bc1f419cebcf => github.com/ca-risken/go-git/v5 v5.4.3-0.20220715100214-652d3d7d4a0e

require (
	github.com/aquasecurity/trivy v0.30.4
	github.com/aquasecurity/trivy-db v0.0.0-20220801073337-2c0339bb9085
	github.com/aws/aws-sdk-go-v2 v1.18.1
	github.com/aws/aws-sdk-go-v2/service/sqs v1.20.8
	github.com/ca-risken/common/pkg/logging v0.0.0-20221119073224-9db027bda6f8
	github.com/ca-risken/common/pkg/profiler v0.0.0-20221119073224-9db027bda6f8
	github.com/ca-risken/common/pkg/sqs v0.0.0-20221119073224-9db027bda6f8
	github.com/ca-risken/common/pkg/tracer v0.0.0-20230727031236-b35703d5c59d
	github.com/ca-risken/core v0.14.0
	github.com/ca-risken/datasource-api v0.16.1-0.20251008060857-a084ce90ef29
	github.com/ca-risken/go-sqs-poller/worker/v5 v5.0.0-20220525093235-9148d33b6aee
	github.com/ca-risken/vulnerability v0.0.0-20250207144506-e2bcae88c3dc
	github.com/cenkalti/backoff/v4 v4.2.0
	github.com/gassara-kys/envconfig v1.4.4
	github.com/go-git/go-git/v5 v5.12.0
	github.com/google/go-cmp v0.6.0
	github.com/google/go-github/v44 v44.1.0
	github.com/spf13/viper v1.13.0
	github.com/stretchr/testify v1.9.0
	github.com/zricethezav/gitleaks/v8 v8.8.6
	golang.org/x/oauth2 v0.7.0
	google.golang.org/grpc v1.54.0
	k8s.io/utils v0.0.0-20221108210102-8e77b1f39fe2
)

require (
	cloud.google.com/go v0.110.0 // indirect
	cloud.google.com/go/accesscontextmanager v1.7.0 // indirect
	cloud.google.com/go/asset v1.13.0 // indirect
	cloud.google.com/go/compute v1.19.0 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	cloud.google.com/go/iam v0.13.0 // indirect
	cloud.google.com/go/longrunning v0.4.1 // indirect
	cloud.google.com/go/orgpolicy v1.10.0 // indirect
	cloud.google.com/go/osconfig v1.11.0 // indirect
	dario.cat/mergo v1.0.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.11.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.7.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.8.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources v1.2.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.2.2 // indirect
	github.com/DATA-DOG/go-sqlmock v1.5.0 // indirect
	github.com/DataDog/appsec-internal-go v1.0.0 // indirect
	github.com/DataDog/datadog-agent/pkg/obfuscate v0.45.0-rc.1 // indirect
	github.com/DataDog/datadog-agent/pkg/remoteconfig/state v0.45.0 // indirect
	github.com/DataDog/datadog-go/v5 v5.1.1 // indirect
	github.com/DataDog/go-libddwaf v1.2.0 // indirect
	github.com/DataDog/go-tuf v0.3.0--fix-localmeta-fork // indirect
	github.com/DataDog/gostackparse v0.6.0 // indirect
	github.com/DataDog/sketches-go v1.4.1 // indirect
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/ProtonMail/go-crypto v1.0.0 // indirect
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.4.10 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.18.21 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.13.20 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.13.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.28 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.0.26 // indirect
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.16.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.13.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/apprunner v1.17.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.26.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.102.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing v1.15.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.19.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/eventbridge v1.18.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/iam v1.21.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.9.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.1.29 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.28 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.14.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/lambda v1.37.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.35.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sns v1.20.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.12.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.14.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.18.9 // indirect
	github.com/aws/smithy-go v1.13.5 // indirect
	github.com/ca-risken/common/pkg/database v0.0.0-20230719091915-496f0dc45899 // indirect
	github.com/ca-risken/common/pkg/rpc v0.0.0-20220601065422-5b97bd6efc9b // indirect
	github.com/caarlos0/env/v6 v6.10.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/coocood/freecache v1.2.3 // indirect
	github.com/cyphar/filepath-securejoin v0.2.4 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/envoyproxy/protoc-gen-validate v0.9.1 // indirect
	github.com/fatih/semgroup v1.2.0 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/gitleaks/go-gitdiff v0.7.6 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.5.0 // indirect
	github.com/go-ozzo/ozzo-validation v3.6.0+incompatible // indirect
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0 // indirect
	github.com/go-sql-driver/mysql v1.7.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.1 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-containerregistry v0.12.0 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/pprof v0.0.0-20230509042627-b1315fad0c5a // indirect
	github.com/google/s2a-go v0.1.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.3 // indirect
	github.com/googleapis/gax-go/v2 v2.8.0 // indirect
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0 // indirect
	github.com/h2non/filetype v1.1.3 // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/magiconair/properties v1.8.6 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/outcaste-io/ristretto v0.2.1 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pelletier/go-toml/v2 v2.2.2 // indirect
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20211021192214-5ab2d9280aa9 // indirect
	github.com/philhofer/fwd v1.1.1 // indirect
	github.com/pjbgf/sha1cd v0.3.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/richardartoul/molecule v1.0.1-0.20221107223329-32cfee06a052 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	github.com/rs/zerolog v1.26.1 // indirect
	github.com/sashabaranov/go-openai v1.5.8 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.6.0 // indirect
	github.com/sergi/go-diff v1.3.2-0.20230802210424-5b0b94c5c0d3 // indirect
	github.com/sirupsen/logrus v1.9.0 // indirect
	github.com/skeema/knownhosts v1.2.2 // indirect
	github.com/slack-go/slack v0.12.2 // indirect
	github.com/spaolacci/murmur3 v0.0.0-20180118202830-f09979ecbc72 // indirect
	github.com/spf13/afero v1.9.2 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/subosito/gotenv v1.4.1 // indirect
	github.com/tinylib/msgp v1.1.6 // indirect
	github.com/vikyd/zero v0.0.0-20190921142904-0f738d0bc858 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go4.org/intern v0.0.0-20220617035311-6925f38cc365 // indirect
	go4.org/unsafe/assume-no-moving-gc v0.0.0-20220617031537-928513b29760 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/net v0.26.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/tools v0.21.1-0.20240508182429-e35e4ccd0d2d // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	google.golang.org/api v0.121.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1 // indirect
	google.golang.org/protobuf v1.34.1 // indirect
	gopkg.in/DataDog/dd-trace-go.v1 v1.52.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gorm.io/driver/mysql v1.5.7 // indirect
	gorm.io/gorm v1.25.12 // indirect
	inet.af/netaddr v0.0.0-20220811202034-502d2d690317 // indirect
)
