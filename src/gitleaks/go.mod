module github.com/ca-risken/code/src/gitleaks

go 1.17

// This is for github.com/zricethezav/gitleaks. Check when update the module.
// https://github.com/zricethezav/gitleaks/blob/v7.5.0/go.mod#L5
replace github.com/go-git/go-git/v5 => github.com/zricethezav/go-git/v5 v5.2.2

require (
	github.com/aws/aws-sdk-go v1.42.22
	github.com/aws/aws-xray-sdk-go v1.6.0
	github.com/ca-risken/code/pkg/common v0.0.0-20220106102406-524b02ed4f0b
	github.com/ca-risken/code/proto/code v0.0.0-20210917082353-3ada53fdb98c
	github.com/ca-risken/common/pkg/logging v0.0.0-20220113015330-0e8462d52b5b
	github.com/ca-risken/common/pkg/sqs v0.0.0-20220113015330-0e8462d52b5b
	github.com/ca-risken/common/pkg/xray v0.0.0-20211118071101-9855266b50a1
	github.com/ca-risken/core/proto/alert v0.0.0-20211207091647-a7dcd065406e
	github.com/ca-risken/core/proto/finding v0.0.0-20211207091647-a7dcd065406e
	github.com/gassara-kys/envconfig v1.4.4
	github.com/gassara-kys/go-sqs-poller/worker/v4 v4.0.0-20210215110542-0be358599a2f
	github.com/google/go-github/v32 v32.1.0
	github.com/google/uuid v1.3.0
	// Gitleaks scanning may fleeze when v1.2.0, so don't udpdate this module
	// github.com/sergi/go-diff v1.1.0 // indirect
	github.com/shurcooL/githubv4 v0.0.0-20210725200734-83ba7b4c9228
	github.com/vikyd/zero v0.0.0-20190921142904-0f738d0bc858
	github.com/zricethezav/gitleaks/v7 v7.5.0
	golang.org/x/oauth2 v0.0.0-20210819190943-2bc19b11175f
	google.golang.org/grpc v1.42.0
)

require (
	github.com/BurntSushi/toml v0.4.1 // indirect
	github.com/Microsoft/go-winio v0.5.0 // indirect
	github.com/andybalholm/brotli v1.0.3 // indirect
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/emirpasic/gods v1.12.0 // indirect
	github.com/go-git/gcfg v1.5.0 // indirect
	github.com/go-git/go-billy/v5 v5.0.0 // indirect
	github.com/go-git/go-git/v5 v5.4.2 // indirect
	github.com/go-ozzo/ozzo-validation v3.6.0+incompatible // indirect
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/imdario/mergo v0.3.9 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jessevdk/go-flags v1.4.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/kevinburke/ssh_config v1.1.0 // indirect
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sergi/go-diff v1.1.0 // indirect
	github.com/shurcooL/graphql v0.0.0-20200928012149-18c5c3165e3a // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.30.0 // indirect
	github.com/xanzy/ssh-agent v0.3.1 // indirect
	golang.org/x/crypto v0.0.0-20210915214749-c084706c2272 // indirect
	golang.org/x/net v0.0.0-20210916014120-12bc252f5db8 // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
	golang.org/x/sys v0.0.0-20220111092808-5a964db01320 // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20210916144049-3192f974c780 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
)
