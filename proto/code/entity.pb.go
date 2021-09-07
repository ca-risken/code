// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.17.3
// source: code/entity.proto

package code

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Type
type Type int32

const (
	Type_UNKNOWN_TYPE Type = 0
	Type_ENTERPRISE   Type = 1
	Type_ORGANIZATION Type = 2
	Type_USER         Type = 3
)

// Enum value maps for Type.
var (
	Type_name = map[int32]string{
		0: "UNKNOWN_TYPE",
		1: "ENTERPRISE",
		2: "ORGANIZATION",
		3: "USER",
	}
	Type_value = map[string]int32{
		"UNKNOWN_TYPE": 0,
		"ENTERPRISE":   1,
		"ORGANIZATION": 2,
		"USER":         3,
	}
)

func (x Type) Enum() *Type {
	p := new(Type)
	*p = x
	return p
}

func (x Type) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Type) Descriptor() protoreflect.EnumDescriptor {
	return file_code_entity_proto_enumTypes[0].Descriptor()
}

func (Type) Type() protoreflect.EnumType {
	return &file_code_entity_proto_enumTypes[0]
}

func (x Type) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Type.Descriptor instead.
func (Type) EnumDescriptor() ([]byte, []int) {
	return file_code_entity_proto_rawDescGZIP(), []int{0}
}

// Status
type Status int32

const (
	Status_UNKNOWN     Status = 0
	Status_OK          Status = 1
	Status_CONFIGURED  Status = 2
	Status_IN_PROGRESS Status = 3
	Status_ERROR       Status = 4
)

// Enum value maps for Status.
var (
	Status_name = map[int32]string{
		0: "UNKNOWN",
		1: "OK",
		2: "CONFIGURED",
		3: "IN_PROGRESS",
		4: "ERROR",
	}
	Status_value = map[string]int32{
		"UNKNOWN":     0,
		"OK":          1,
		"CONFIGURED":  2,
		"IN_PROGRESS": 3,
		"ERROR":       4,
	}
)

func (x Status) Enum() *Status {
	p := new(Status)
	*p = x
	return p
}

func (x Status) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Status) Descriptor() protoreflect.EnumDescriptor {
	return file_code_entity_proto_enumTypes[1].Descriptor()
}

func (Status) Type() protoreflect.EnumType {
	return &file_code_entity_proto_enumTypes[1]
}

func (x Status) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Status.Descriptor instead.
func (Status) EnumDescriptor() ([]byte, []int) {
	return file_code_entity_proto_rawDescGZIP(), []int{1}
}

// CodeDataSource
type CodeDataSource struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CodeDataSourceId uint32  `protobuf:"varint,1,opt,name=code_data_source_id,json=codeDataSourceId,proto3" json:"code_data_source_id,omitempty"`
	Name             string  `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Description      string  `protobuf:"bytes,3,opt,name=description,proto3" json:"description,omitempty"`
	MaxScore         float32 `protobuf:"fixed32,4,opt,name=max_score,json=maxScore,proto3" json:"max_score,omitempty"`
	CreatedAt        int64   `protobuf:"varint,5,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	UpdatedAt        int64   `protobuf:"varint,6,opt,name=updated_at,json=updatedAt,proto3" json:"updated_at,omitempty"`
}

func (x *CodeDataSource) Reset() {
	*x = CodeDataSource{}
	if protoimpl.UnsafeEnabled {
		mi := &file_code_entity_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CodeDataSource) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CodeDataSource) ProtoMessage() {}

func (x *CodeDataSource) ProtoReflect() protoreflect.Message {
	mi := &file_code_entity_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CodeDataSource.ProtoReflect.Descriptor instead.
func (*CodeDataSource) Descriptor() ([]byte, []int) {
	return file_code_entity_proto_rawDescGZIP(), []int{0}
}

func (x *CodeDataSource) GetCodeDataSourceId() uint32 {
	if x != nil {
		return x.CodeDataSourceId
	}
	return 0
}

func (x *CodeDataSource) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *CodeDataSource) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *CodeDataSource) GetMaxScore() float32 {
	if x != nil {
		return x.MaxScore
	}
	return 0
}

func (x *CodeDataSource) GetCreatedAt() int64 {
	if x != nil {
		return x.CreatedAt
	}
	return 0
}

func (x *CodeDataSource) GetUpdatedAt() int64 {
	if x != nil {
		return x.UpdatedAt
	}
	return 0
}

// Gitleaks
type Gitleaks struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	GitleaksId          uint32 `protobuf:"varint,1,opt,name=gitleaks_id,json=gitleaksId,proto3" json:"gitleaks_id,omitempty"`
	CodeDataSourceId    uint32 `protobuf:"varint,2,opt,name=code_data_source_id,json=codeDataSourceId,proto3" json:"code_data_source_id,omitempty"`
	Name                string `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`
	ProjectId           uint32 `protobuf:"varint,4,opt,name=project_id,json=projectId,proto3" json:"project_id,omitempty"`
	Type                Type   `protobuf:"varint,5,opt,name=type,proto3,enum=code.code.Type" json:"type,omitempty"`
	BaseUrl             string `protobuf:"bytes,6,opt,name=base_url,json=baseUrl,proto3" json:"base_url,omitempty"`
	TargetResource      string `protobuf:"bytes,7,opt,name=target_resource,json=targetResource,proto3" json:"target_resource,omitempty"`
	RepositoryPattern   string `protobuf:"bytes,8,opt,name=repository_pattern,json=repositoryPattern,proto3" json:"repository_pattern,omitempty"`
	GithubUser          string `protobuf:"bytes,9,opt,name=github_user,json=githubUser,proto3" json:"github_user,omitempty"`
	PersonalAccessToken string `protobuf:"bytes,10,opt,name=personal_access_token,json=personalAccessToken,proto3" json:"personal_access_token,omitempty"`
	ScanPublic          bool   `protobuf:"varint,11,opt,name=scan_public,json=scanPublic,proto3" json:"scan_public,omitempty"`
	ScanInternal        bool   `protobuf:"varint,12,opt,name=scan_internal,json=scanInternal,proto3" json:"scan_internal,omitempty"`
	ScanPrivate         bool   `protobuf:"varint,13,opt,name=scan_private,json=scanPrivate,proto3" json:"scan_private,omitempty"`
	GitleaksConfig      string `protobuf:"bytes,14,opt,name=gitleaks_config,json=gitleaksConfig,proto3" json:"gitleaks_config,omitempty"`
	Status              Status `protobuf:"varint,15,opt,name=status,proto3,enum=code.code.Status" json:"status,omitempty"`
	StatusDetail        string `protobuf:"bytes,16,opt,name=status_detail,json=statusDetail,proto3" json:"status_detail,omitempty"`
	ScanAt              int64  `protobuf:"varint,17,opt,name=scan_at,json=scanAt,proto3" json:"scan_at,omitempty"`
	CreatedAt           int64  `protobuf:"varint,18,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	UpdatedAt           int64  `protobuf:"varint,19,opt,name=updated_at,json=updatedAt,proto3" json:"updated_at,omitempty"`
}

func (x *Gitleaks) Reset() {
	*x = Gitleaks{}
	if protoimpl.UnsafeEnabled {
		mi := &file_code_entity_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Gitleaks) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Gitleaks) ProtoMessage() {}

func (x *Gitleaks) ProtoReflect() protoreflect.Message {
	mi := &file_code_entity_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Gitleaks.ProtoReflect.Descriptor instead.
func (*Gitleaks) Descriptor() ([]byte, []int) {
	return file_code_entity_proto_rawDescGZIP(), []int{1}
}

func (x *Gitleaks) GetGitleaksId() uint32 {
	if x != nil {
		return x.GitleaksId
	}
	return 0
}

func (x *Gitleaks) GetCodeDataSourceId() uint32 {
	if x != nil {
		return x.CodeDataSourceId
	}
	return 0
}

func (x *Gitleaks) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Gitleaks) GetProjectId() uint32 {
	if x != nil {
		return x.ProjectId
	}
	return 0
}

func (x *Gitleaks) GetType() Type {
	if x != nil {
		return x.Type
	}
	return Type_UNKNOWN_TYPE
}

func (x *Gitleaks) GetBaseUrl() string {
	if x != nil {
		return x.BaseUrl
	}
	return ""
}

func (x *Gitleaks) GetTargetResource() string {
	if x != nil {
		return x.TargetResource
	}
	return ""
}

func (x *Gitleaks) GetRepositoryPattern() string {
	if x != nil {
		return x.RepositoryPattern
	}
	return ""
}

func (x *Gitleaks) GetGithubUser() string {
	if x != nil {
		return x.GithubUser
	}
	return ""
}

func (x *Gitleaks) GetPersonalAccessToken() string {
	if x != nil {
		return x.PersonalAccessToken
	}
	return ""
}

func (x *Gitleaks) GetScanPublic() bool {
	if x != nil {
		return x.ScanPublic
	}
	return false
}

func (x *Gitleaks) GetScanInternal() bool {
	if x != nil {
		return x.ScanInternal
	}
	return false
}

func (x *Gitleaks) GetScanPrivate() bool {
	if x != nil {
		return x.ScanPrivate
	}
	return false
}

func (x *Gitleaks) GetGitleaksConfig() string {
	if x != nil {
		return x.GitleaksConfig
	}
	return ""
}

func (x *Gitleaks) GetStatus() Status {
	if x != nil {
		return x.Status
	}
	return Status_UNKNOWN
}

func (x *Gitleaks) GetStatusDetail() string {
	if x != nil {
		return x.StatusDetail
	}
	return ""
}

func (x *Gitleaks) GetScanAt() int64 {
	if x != nil {
		return x.ScanAt
	}
	return 0
}

func (x *Gitleaks) GetCreatedAt() int64 {
	if x != nil {
		return x.CreatedAt
	}
	return 0
}

func (x *Gitleaks) GetUpdatedAt() int64 {
	if x != nil {
		return x.UpdatedAt
	}
	return 0
}

// GitleaksForUpsert
type GitleaksForUpsert struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	GitleaksId          uint32 `protobuf:"varint,1,opt,name=gitleaks_id,json=gitleaksId,proto3" json:"gitleaks_id,omitempty"` // Unique key for Gitleaks entity.
	CodeDataSourceId    uint32 `protobuf:"varint,2,opt,name=code_data_source_id,json=codeDataSourceId,proto3" json:"code_data_source_id,omitempty"`
	Name                string `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`
	ProjectId           uint32 `protobuf:"varint,4,opt,name=project_id,json=projectId,proto3" json:"project_id,omitempty"`
	Type                Type   `protobuf:"varint,5,opt,name=type,proto3,enum=code.code.Type" json:"type,omitempty"`
	BaseUrl             string `protobuf:"bytes,6,opt,name=base_url,json=baseUrl,proto3" json:"base_url,omitempty"`
	TargetResource      string `protobuf:"bytes,7,opt,name=target_resource,json=targetResource,proto3" json:"target_resource,omitempty"`
	RepositoryPattern   string `protobuf:"bytes,8,opt,name=repository_pattern,json=repositoryPattern,proto3" json:"repository_pattern,omitempty"`
	GithubUser          string `protobuf:"bytes,9,opt,name=github_user,json=githubUser,proto3" json:"github_user,omitempty"`
	PersonalAccessToken string `protobuf:"bytes,10,opt,name=personal_access_token,json=personalAccessToken,proto3" json:"personal_access_token,omitempty"`
	ScanPublic          bool   `protobuf:"varint,11,opt,name=scan_public,json=scanPublic,proto3" json:"scan_public,omitempty"`
	ScanInternal        bool   `protobuf:"varint,12,opt,name=scan_internal,json=scanInternal,proto3" json:"scan_internal,omitempty"`
	ScanPrivate         bool   `protobuf:"varint,13,opt,name=scan_private,json=scanPrivate,proto3" json:"scan_private,omitempty"`
	GitleaksConfig      string `protobuf:"bytes,14,opt,name=gitleaks_config,json=gitleaksConfig,proto3" json:"gitleaks_config,omitempty"`
	Status              Status `protobuf:"varint,15,opt,name=status,proto3,enum=code.code.Status" json:"status,omitempty"`
	StatusDetail        string `protobuf:"bytes,16,opt,name=status_detail,json=statusDetail,proto3" json:"status_detail,omitempty"`
	ScanAt              int64  `protobuf:"varint,17,opt,name=scan_at,json=scanAt,proto3" json:"scan_at,omitempty"`
}

func (x *GitleaksForUpsert) Reset() {
	*x = GitleaksForUpsert{}
	if protoimpl.UnsafeEnabled {
		mi := &file_code_entity_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GitleaksForUpsert) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GitleaksForUpsert) ProtoMessage() {}

func (x *GitleaksForUpsert) ProtoReflect() protoreflect.Message {
	mi := &file_code_entity_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GitleaksForUpsert.ProtoReflect.Descriptor instead.
func (*GitleaksForUpsert) Descriptor() ([]byte, []int) {
	return file_code_entity_proto_rawDescGZIP(), []int{2}
}

func (x *GitleaksForUpsert) GetGitleaksId() uint32 {
	if x != nil {
		return x.GitleaksId
	}
	return 0
}

func (x *GitleaksForUpsert) GetCodeDataSourceId() uint32 {
	if x != nil {
		return x.CodeDataSourceId
	}
	return 0
}

func (x *GitleaksForUpsert) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *GitleaksForUpsert) GetProjectId() uint32 {
	if x != nil {
		return x.ProjectId
	}
	return 0
}

func (x *GitleaksForUpsert) GetType() Type {
	if x != nil {
		return x.Type
	}
	return Type_UNKNOWN_TYPE
}

func (x *GitleaksForUpsert) GetBaseUrl() string {
	if x != nil {
		return x.BaseUrl
	}
	return ""
}

func (x *GitleaksForUpsert) GetTargetResource() string {
	if x != nil {
		return x.TargetResource
	}
	return ""
}

func (x *GitleaksForUpsert) GetRepositoryPattern() string {
	if x != nil {
		return x.RepositoryPattern
	}
	return ""
}

func (x *GitleaksForUpsert) GetGithubUser() string {
	if x != nil {
		return x.GithubUser
	}
	return ""
}

func (x *GitleaksForUpsert) GetPersonalAccessToken() string {
	if x != nil {
		return x.PersonalAccessToken
	}
	return ""
}

func (x *GitleaksForUpsert) GetScanPublic() bool {
	if x != nil {
		return x.ScanPublic
	}
	return false
}

func (x *GitleaksForUpsert) GetScanInternal() bool {
	if x != nil {
		return x.ScanInternal
	}
	return false
}

func (x *GitleaksForUpsert) GetScanPrivate() bool {
	if x != nil {
		return x.ScanPrivate
	}
	return false
}

func (x *GitleaksForUpsert) GetGitleaksConfig() string {
	if x != nil {
		return x.GitleaksConfig
	}
	return ""
}

func (x *GitleaksForUpsert) GetStatus() Status {
	if x != nil {
		return x.Status
	}
	return Status_UNKNOWN
}

func (x *GitleaksForUpsert) GetStatusDetail() string {
	if x != nil {
		return x.StatusDetail
	}
	return ""
}

func (x *GitleaksForUpsert) GetScanAt() int64 {
	if x != nil {
		return x.ScanAt
	}
	return 0
}

// EnterpriseOrg
type EnterpriseOrg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	GitleaksId uint32 `protobuf:"varint,1,opt,name=gitleaks_id,json=gitleaksId,proto3" json:"gitleaks_id,omitempty"`
	Login      string `protobuf:"bytes,2,opt,name=login,proto3" json:"login,omitempty"`
	ProjectId  uint32 `protobuf:"varint,3,opt,name=project_id,json=projectId,proto3" json:"project_id,omitempty"`
	CreatedAt  int64  `protobuf:"varint,4,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	UpdatedAt  int64  `protobuf:"varint,5,opt,name=updated_at,json=updatedAt,proto3" json:"updated_at,omitempty"`
}

func (x *EnterpriseOrg) Reset() {
	*x = EnterpriseOrg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_code_entity_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EnterpriseOrg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnterpriseOrg) ProtoMessage() {}

func (x *EnterpriseOrg) ProtoReflect() protoreflect.Message {
	mi := &file_code_entity_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EnterpriseOrg.ProtoReflect.Descriptor instead.
func (*EnterpriseOrg) Descriptor() ([]byte, []int) {
	return file_code_entity_proto_rawDescGZIP(), []int{3}
}

func (x *EnterpriseOrg) GetGitleaksId() uint32 {
	if x != nil {
		return x.GitleaksId
	}
	return 0
}

func (x *EnterpriseOrg) GetLogin() string {
	if x != nil {
		return x.Login
	}
	return ""
}

func (x *EnterpriseOrg) GetProjectId() uint32 {
	if x != nil {
		return x.ProjectId
	}
	return 0
}

func (x *EnterpriseOrg) GetCreatedAt() int64 {
	if x != nil {
		return x.CreatedAt
	}
	return 0
}

func (x *EnterpriseOrg) GetUpdatedAt() int64 {
	if x != nil {
		return x.UpdatedAt
	}
	return 0
}

// EnterpriseOrgForUpsert
type EnterpriseOrgForUpsert struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	GitleaksId uint32 `protobuf:"varint,1,opt,name=gitleaks_id,json=gitleaksId,proto3" json:"gitleaks_id,omitempty"`
	Login      string `protobuf:"bytes,2,opt,name=login,proto3" json:"login,omitempty"`
	ProjectId  uint32 `protobuf:"varint,3,opt,name=project_id,json=projectId,proto3" json:"project_id,omitempty"`
}

func (x *EnterpriseOrgForUpsert) Reset() {
	*x = EnterpriseOrgForUpsert{}
	if protoimpl.UnsafeEnabled {
		mi := &file_code_entity_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EnterpriseOrgForUpsert) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnterpriseOrgForUpsert) ProtoMessage() {}

func (x *EnterpriseOrgForUpsert) ProtoReflect() protoreflect.Message {
	mi := &file_code_entity_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EnterpriseOrgForUpsert.ProtoReflect.Descriptor instead.
func (*EnterpriseOrgForUpsert) Descriptor() ([]byte, []int) {
	return file_code_entity_proto_rawDescGZIP(), []int{4}
}

func (x *EnterpriseOrgForUpsert) GetGitleaksId() uint32 {
	if x != nil {
		return x.GitleaksId
	}
	return 0
}

func (x *EnterpriseOrgForUpsert) GetLogin() string {
	if x != nil {
		return x.Login
	}
	return ""
}

func (x *EnterpriseOrgForUpsert) GetProjectId() uint32 {
	if x != nil {
		return x.ProjectId
	}
	return 0
}

var File_code_entity_proto protoreflect.FileDescriptor

var file_code_entity_proto_rawDesc = []byte{
	0x0a, 0x11, 0x63, 0x6f, 0x64, 0x65, 0x2f, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x09, 0x63, 0x6f, 0x64, 0x65, 0x2e, 0x63, 0x6f, 0x64, 0x65, 0x22, 0xd0,
	0x01, 0x0a, 0x0e, 0x43, 0x6f, 0x64, 0x65, 0x44, 0x61, 0x74, 0x61, 0x53, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x12, 0x2d, 0x0a, 0x13, 0x63, 0x6f, 0x64, 0x65, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x10,
	0x63, 0x6f, 0x64, 0x65, 0x44, 0x61, 0x74, 0x61, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x64,
	0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72,
	0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1b, 0x0a, 0x09, 0x6d, 0x61, 0x78, 0x5f, 0x73, 0x63,
	0x6f, 0x72, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x02, 0x52, 0x08, 0x6d, 0x61, 0x78, 0x53, 0x63,
	0x6f, 0x72, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61,
	0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64,
	0x41, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41,
	0x74, 0x22, 0xb3, 0x05, 0x0a, 0x08, 0x47, 0x69, 0x74, 0x6c, 0x65, 0x61, 0x6b, 0x73, 0x12, 0x1f,
	0x0a, 0x0b, 0x67, 0x69, 0x74, 0x6c, 0x65, 0x61, 0x6b, 0x73, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x0a, 0x67, 0x69, 0x74, 0x6c, 0x65, 0x61, 0x6b, 0x73, 0x49, 0x64, 0x12,
	0x2d, 0x0a, 0x13, 0x63, 0x6f, 0x64, 0x65, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x10, 0x63, 0x6f,
	0x64, 0x65, 0x44, 0x61, 0x74, 0x61, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x64, 0x12, 0x12,
	0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x69, 0x64,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x49,
	0x64, 0x12, 0x23, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0e, 0x32,
	0x0f, 0x2e, 0x63, 0x6f, 0x64, 0x65, 0x2e, 0x63, 0x6f, 0x64, 0x65, 0x2e, 0x54, 0x79, 0x70, 0x65,
	0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x62, 0x61, 0x73, 0x65, 0x5f, 0x75,
	0x72, 0x6c, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x62, 0x61, 0x73, 0x65, 0x55, 0x72,
	0x6c, 0x12, 0x27, 0x0a, 0x0f, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x72, 0x65, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x74, 0x61, 0x72, 0x67,
	0x65, 0x74, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x2d, 0x0a, 0x12, 0x72, 0x65,
	0x70, 0x6f, 0x73, 0x69, 0x74, 0x6f, 0x72, 0x79, 0x5f, 0x70, 0x61, 0x74, 0x74, 0x65, 0x72, 0x6e,
	0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x11, 0x72, 0x65, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x6f,
	0x72, 0x79, 0x50, 0x61, 0x74, 0x74, 0x65, 0x72, 0x6e, 0x12, 0x1f, 0x0a, 0x0b, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x5f, 0x75, 0x73, 0x65, 0x72, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x55, 0x73, 0x65, 0x72, 0x12, 0x32, 0x0a, 0x15, 0x70, 0x65,
	0x72, 0x73, 0x6f, 0x6e, 0x61, 0x6c, 0x5f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x74, 0x6f,
	0x6b, 0x65, 0x6e, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x13, 0x70, 0x65, 0x72, 0x73, 0x6f,
	0x6e, 0x61, 0x6c, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x1f,
	0x0a, 0x0b, 0x73, 0x63, 0x61, 0x6e, 0x5f, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x18, 0x0b, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x0a, 0x73, 0x63, 0x61, 0x6e, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x12,
	0x23, 0x0a, 0x0d, 0x73, 0x63, 0x61, 0x6e, 0x5f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c,
	0x18, 0x0c, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0c, 0x73, 0x63, 0x61, 0x6e, 0x49, 0x6e, 0x74, 0x65,
	0x72, 0x6e, 0x61, 0x6c, 0x12, 0x21, 0x0a, 0x0c, 0x73, 0x63, 0x61, 0x6e, 0x5f, 0x70, 0x72, 0x69,
	0x76, 0x61, 0x74, 0x65, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x73, 0x63, 0x61, 0x6e,
	0x50, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x12, 0x27, 0x0a, 0x0f, 0x67, 0x69, 0x74, 0x6c, 0x65,
	0x61, 0x6b, 0x73, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0e, 0x67, 0x69, 0x74, 0x6c, 0x65, 0x61, 0x6b, 0x73, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x12, 0x29, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x0e,
	0x32, 0x11, 0x2e, 0x63, 0x6f, 0x64, 0x65, 0x2e, 0x63, 0x6f, 0x64, 0x65, 0x2e, 0x53, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x23, 0x0a, 0x0d, 0x73,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x5f, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x18, 0x10, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0c, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c,
	0x12, 0x17, 0x0a, 0x07, 0x73, 0x63, 0x61, 0x6e, 0x5f, 0x61, 0x74, 0x18, 0x11, 0x20, 0x01, 0x28,
	0x03, 0x52, 0x06, 0x73, 0x63, 0x61, 0x6e, 0x41, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x12, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x63,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x75, 0x70, 0x64, 0x61,
	0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x13, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x75, 0x70,
	0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x22, 0xfe, 0x04, 0x0a, 0x11, 0x47, 0x69, 0x74, 0x6c,
	0x65, 0x61, 0x6b, 0x73, 0x46, 0x6f, 0x72, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74, 0x12, 0x1f, 0x0a,
	0x0b, 0x67, 0x69, 0x74, 0x6c, 0x65, 0x61, 0x6b, 0x73, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x0a, 0x67, 0x69, 0x74, 0x6c, 0x65, 0x61, 0x6b, 0x73, 0x49, 0x64, 0x12, 0x2d,
	0x0a, 0x13, 0x63, 0x6f, 0x64, 0x65, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x10, 0x63, 0x6f, 0x64,
	0x65, 0x44, 0x61, 0x74, 0x61, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x64, 0x12, 0x12, 0x0a,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x69, 0x64, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x64,
	0x12, 0x23, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0f,
	0x2e, 0x63, 0x6f, 0x64, 0x65, 0x2e, 0x63, 0x6f, 0x64, 0x65, 0x2e, 0x54, 0x79, 0x70, 0x65, 0x52,
	0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x62, 0x61, 0x73, 0x65, 0x5f, 0x75, 0x72,
	0x6c, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x62, 0x61, 0x73, 0x65, 0x55, 0x72, 0x6c,
	0x12, 0x27, 0x0a, 0x0f, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x72, 0x65, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x74, 0x61, 0x72, 0x67, 0x65,
	0x74, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x2d, 0x0a, 0x12, 0x72, 0x65, 0x70,
	0x6f, 0x73, 0x69, 0x74, 0x6f, 0x72, 0x79, 0x5f, 0x70, 0x61, 0x74, 0x74, 0x65, 0x72, 0x6e, 0x18,
	0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x11, 0x72, 0x65, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x6f, 0x72,
	0x79, 0x50, 0x61, 0x74, 0x74, 0x65, 0x72, 0x6e, 0x12, 0x1f, 0x0a, 0x0b, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x5f, 0x75, 0x73, 0x65, 0x72, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x55, 0x73, 0x65, 0x72, 0x12, 0x32, 0x0a, 0x15, 0x70, 0x65, 0x72,
	0x73, 0x6f, 0x6e, 0x61, 0x6c, 0x5f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x74, 0x6f, 0x6b,
	0x65, 0x6e, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x13, 0x70, 0x65, 0x72, 0x73, 0x6f, 0x6e,
	0x61, 0x6c, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x1f, 0x0a,
	0x0b, 0x73, 0x63, 0x61, 0x6e, 0x5f, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x18, 0x0b, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x0a, 0x73, 0x63, 0x61, 0x6e, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x12, 0x23,
	0x0a, 0x0d, 0x73, 0x63, 0x61, 0x6e, 0x5f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x18,
	0x0c, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0c, 0x73, 0x63, 0x61, 0x6e, 0x49, 0x6e, 0x74, 0x65, 0x72,
	0x6e, 0x61, 0x6c, 0x12, 0x21, 0x0a, 0x0c, 0x73, 0x63, 0x61, 0x6e, 0x5f, 0x70, 0x72, 0x69, 0x76,
	0x61, 0x74, 0x65, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x73, 0x63, 0x61, 0x6e, 0x50,
	0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x12, 0x27, 0x0a, 0x0f, 0x67, 0x69, 0x74, 0x6c, 0x65, 0x61,
	0x6b, 0x73, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0e, 0x67, 0x69, 0x74, 0x6c, 0x65, 0x61, 0x6b, 0x73, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12,
	0x29, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x0e, 0x32,
	0x11, 0x2e, 0x63, 0x6f, 0x64, 0x65, 0x2e, 0x63, 0x6f, 0x64, 0x65, 0x2e, 0x53, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x23, 0x0a, 0x0d, 0x73, 0x74,
	0x61, 0x74, 0x75, 0x73, 0x5f, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x18, 0x10, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0c, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x12,
	0x17, 0x0a, 0x07, 0x73, 0x63, 0x61, 0x6e, 0x5f, 0x61, 0x74, 0x18, 0x11, 0x20, 0x01, 0x28, 0x03,
	0x52, 0x06, 0x73, 0x63, 0x61, 0x6e, 0x41, 0x74, 0x22, 0xa3, 0x01, 0x0a, 0x0d, 0x45, 0x6e, 0x74,
	0x65, 0x72, 0x70, 0x72, 0x69, 0x73, 0x65, 0x4f, 0x72, 0x67, 0x12, 0x1f, 0x0a, 0x0b, 0x67, 0x69,
	0x74, 0x6c, 0x65, 0x61, 0x6b, 0x73, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x0a, 0x67, 0x69, 0x74, 0x6c, 0x65, 0x61, 0x6b, 0x73, 0x49, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x6c,
	0x6f, 0x67, 0x69, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6c, 0x6f, 0x67, 0x69,
	0x6e, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x69, 0x64, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x64,
	0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12,
	0x1d, 0x0a, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x03, 0x52, 0x09, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x22, 0x6e,
	0x0a, 0x16, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x70, 0x72, 0x69, 0x73, 0x65, 0x4f, 0x72, 0x67, 0x46,
	0x6f, 0x72, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74, 0x12, 0x1f, 0x0a, 0x0b, 0x67, 0x69, 0x74, 0x6c,
	0x65, 0x61, 0x6b, 0x73, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a, 0x67,
	0x69, 0x74, 0x6c, 0x65, 0x61, 0x6b, 0x73, 0x49, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x6c, 0x6f, 0x67,
	0x69, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x12,
	0x1d, 0x0a, 0x0a, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x09, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x64, 0x2a, 0x44,
	0x0a, 0x04, 0x54, 0x79, 0x70, 0x65, 0x12, 0x10, 0x0a, 0x0c, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57,
	0x4e, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x10, 0x00, 0x12, 0x0e, 0x0a, 0x0a, 0x45, 0x4e, 0x54, 0x45,
	0x52, 0x50, 0x52, 0x49, 0x53, 0x45, 0x10, 0x01, 0x12, 0x10, 0x0a, 0x0c, 0x4f, 0x52, 0x47, 0x41,
	0x4e, 0x49, 0x5a, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x10, 0x02, 0x12, 0x08, 0x0a, 0x04, 0x55, 0x53,
	0x45, 0x52, 0x10, 0x03, 0x2a, 0x49, 0x0a, 0x06, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x0b,
	0x0a, 0x07, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x00, 0x12, 0x06, 0x0a, 0x02, 0x4f,
	0x4b, 0x10, 0x01, 0x12, 0x0e, 0x0a, 0x0a, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x55, 0x52, 0x45,
	0x44, 0x10, 0x02, 0x12, 0x0f, 0x0a, 0x0b, 0x49, 0x4e, 0x5f, 0x50, 0x52, 0x4f, 0x47, 0x52, 0x45,
	0x53, 0x53, 0x10, 0x03, 0x12, 0x09, 0x0a, 0x05, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x10, 0x04, 0x42,
	0x26, 0x5a, 0x24, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x61,
	0x2d, 0x72, 0x69, 0x73, 0x6b, 0x65, 0x6e, 0x2f, 0x63, 0x6f, 0x64, 0x65, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x64, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_code_entity_proto_rawDescOnce sync.Once
	file_code_entity_proto_rawDescData = file_code_entity_proto_rawDesc
)

func file_code_entity_proto_rawDescGZIP() []byte {
	file_code_entity_proto_rawDescOnce.Do(func() {
		file_code_entity_proto_rawDescData = protoimpl.X.CompressGZIP(file_code_entity_proto_rawDescData)
	})
	return file_code_entity_proto_rawDescData
}

var file_code_entity_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_code_entity_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_code_entity_proto_goTypes = []interface{}{
	(Type)(0),                      // 0: code.code.Type
	(Status)(0),                    // 1: code.code.Status
	(*CodeDataSource)(nil),         // 2: code.code.CodeDataSource
	(*Gitleaks)(nil),               // 3: code.code.Gitleaks
	(*GitleaksForUpsert)(nil),      // 4: code.code.GitleaksForUpsert
	(*EnterpriseOrg)(nil),          // 5: code.code.EnterpriseOrg
	(*EnterpriseOrgForUpsert)(nil), // 6: code.code.EnterpriseOrgForUpsert
}
var file_code_entity_proto_depIdxs = []int32{
	0, // 0: code.code.Gitleaks.type:type_name -> code.code.Type
	1, // 1: code.code.Gitleaks.status:type_name -> code.code.Status
	0, // 2: code.code.GitleaksForUpsert.type:type_name -> code.code.Type
	1, // 3: code.code.GitleaksForUpsert.status:type_name -> code.code.Status
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_code_entity_proto_init() }
func file_code_entity_proto_init() {
	if File_code_entity_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_code_entity_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CodeDataSource); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_code_entity_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Gitleaks); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_code_entity_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GitleaksForUpsert); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_code_entity_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EnterpriseOrg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_code_entity_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EnterpriseOrgForUpsert); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_code_entity_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_code_entity_proto_goTypes,
		DependencyIndexes: file_code_entity_proto_depIdxs,
		EnumInfos:         file_code_entity_proto_enumTypes,
		MessageInfos:      file_code_entity_proto_msgTypes,
	}.Build()
	File_code_entity_proto = out.File
	file_code_entity_proto_rawDesc = nil
	file_code_entity_proto_goTypes = nil
	file_code_entity_proto_depIdxs = nil
}
