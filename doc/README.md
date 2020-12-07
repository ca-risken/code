# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [code/entity.proto](#code/entity.proto)
    - [CodeDataSource](#code.code.CodeDataSource)
    - [EnterpriseOrg](#code.code.EnterpriseOrg)
    - [EnterpriseOrgForUpsert](#code.code.EnterpriseOrgForUpsert)
    - [Gitleaks](#code.code.Gitleaks)
    - [GitleaksForUpsert](#code.code.GitleaksForUpsert)
  
    - [Status](#code.code.Status)
    - [Type](#code.code.Type)
  
- [code/service.proto](#code/service.proto)
    - [DeleteEnterpriseOrgRequest](#code.code.DeleteEnterpriseOrgRequest)
    - [DeleteGitleaksRequest](#code.code.DeleteGitleaksRequest)
    - [InvokeScanGitleaksRequest](#code.code.InvokeScanGitleaksRequest)
    - [ListDataSourceRequest](#code.code.ListDataSourceRequest)
    - [ListDataSourceResponse](#code.code.ListDataSourceResponse)
    - [ListEnterpriseOrgRequest](#code.code.ListEnterpriseOrgRequest)
    - [ListEnterpriseOrgResponse](#code.code.ListEnterpriseOrgResponse)
    - [ListGitleaksRequest](#code.code.ListGitleaksRequest)
    - [ListGitleaksResponse](#code.code.ListGitleaksResponse)
    - [PutEnterpriseOrgRequest](#code.code.PutEnterpriseOrgRequest)
    - [PutEnterpriseOrgResponse](#code.code.PutEnterpriseOrgResponse)
    - [PutGitleaksRequest](#code.code.PutGitleaksRequest)
    - [PutGitleaksResponse](#code.code.PutGitleaksResponse)
  
    - [CodeService](#code.code.CodeService)
  
- [Scalar Value Types](#scalar-value-types)



<a name="code/entity.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## code/entity.proto



<a name="code.code.CodeDataSource"></a>

### CodeDataSource
CodeDataSource


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| code_data_source_id | [uint32](#uint32) |  |  |
| name | [string](#string) |  |  |
| description | [string](#string) |  |  |
| max_score | [float](#float) |  |  |
| created_at | [int64](#int64) |  |  |
| updated_at | [int64](#int64) |  |  |






<a name="code.code.EnterpriseOrg"></a>

### EnterpriseOrg
EnterpriseOrg


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| gitleaks_id | [uint32](#uint32) |  |  |
| login | [string](#string) |  |  |
| project_id | [uint32](#uint32) |  |  |
| created_at | [int64](#int64) |  |  |
| updated_at | [int64](#int64) |  |  |






<a name="code.code.EnterpriseOrgForUpsert"></a>

### EnterpriseOrgForUpsert
EnterpriseOrgForUpsert


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| gitleaks_id | [uint32](#uint32) |  |  |
| login | [string](#string) |  |  |
| project_id | [uint32](#uint32) |  |  |






<a name="code.code.Gitleaks"></a>

### Gitleaks
Gitleaks


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| gitleaks_id | [uint32](#uint32) |  |  |
| code_data_source_id | [uint32](#uint32) |  |  |
| name | [string](#string) |  |  |
| project_id | [uint32](#uint32) |  |  |
| type | [Type](#code.code.Type) |  |  |
| target_resource | [string](#string) |  |  |
| repository_pattern | [string](#string) |  |  |
| github_user | [string](#string) |  |  |
| personal_access_token | [string](#string) |  |  |
| scan_pubilc | [bool](#bool) |  |  |
| scan_internal | [bool](#bool) |  |  |
| scan_private | [bool](#bool) |  |  |
| gitleaks_config | [string](#string) |  |  |
| status | [Status](#code.code.Status) |  |  |
| status_detail | [string](#string) |  |  |
| scan_at | [int64](#int64) |  |  |
| created_at | [int64](#int64) |  |  |
| updated_at | [int64](#int64) |  |  |






<a name="code.code.GitleaksForUpsert"></a>

### GitleaksForUpsert
GitleaksForUpsert


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| gitleaks_id | [uint32](#uint32) |  | Unique key for Gitleaks entity. |
| code_data_source_id | [uint32](#uint32) |  |  |
| name | [string](#string) |  |  |
| project_id | [uint32](#uint32) |  |  |
| type | [Type](#code.code.Type) |  |  |
| target_resource | [string](#string) |  |  |
| repository_pattern | [string](#string) |  |  |
| github_user | [string](#string) |  |  |
| personal_access_token | [string](#string) |  |  |
| scan_pubilc | [bool](#bool) |  |  |
| scan_internal | [bool](#bool) |  |  |
| scan_private | [bool](#bool) |  |  |
| gitleaks_config | [string](#string) |  |  |
| status | [Status](#code.code.Status) |  |  |
| status_detail | [string](#string) |  |  |
| scan_at | [int64](#int64) |  |  |





 


<a name="code.code.Status"></a>

### Status
Status

| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN | 0 |  |
| OK | 1 |  |
| CONFIGURED | 2 |  |
| NOT_CONFIGURED | 3 |  |
| ERROR | 4 |  |



<a name="code.code.Type"></a>

### Type
Type

| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN_TYPE | 0 |  |
| ENTERPRISE | 1 |  |
| ORGANIZATION | 2 |  |
| USER | 3 |  |


 

 

 



<a name="code/service.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## code/service.proto



<a name="code.code.DeleteEnterpriseOrgRequest"></a>

### DeleteEnterpriseOrgRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| project_id | [uint32](#uint32) |  |  |
| gitleaks_id | [uint32](#uint32) |  |  |






<a name="code.code.DeleteGitleaksRequest"></a>

### DeleteGitleaksRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| project_id | [uint32](#uint32) |  |  |
| gitleaks_id | [uint32](#uint32) |  |  |






<a name="code.code.InvokeScanGitleaksRequest"></a>

### InvokeScanGitleaksRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| project_id | [uint32](#uint32) |  |  |
| gitleaks_id | [uint32](#uint32) |  |  |






<a name="code.code.ListDataSourceRequest"></a>

### ListDataSourceRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| code_data_source_id | [uint32](#uint32) |  |  |
| name | [string](#string) |  |  |






<a name="code.code.ListDataSourceResponse"></a>

### ListDataSourceResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| code_data_source | [CodeDataSource](#code.code.CodeDataSource) | repeated |  |






<a name="code.code.ListEnterpriseOrgRequest"></a>

### ListEnterpriseOrgRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| project_id | [uint32](#uint32) |  |  |
| gitleaks_id | [uint32](#uint32) |  |  |






<a name="code.code.ListEnterpriseOrgResponse"></a>

### ListEnterpriseOrgResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| enterprise_org | [EnterpriseOrg](#code.code.EnterpriseOrg) | repeated |  |






<a name="code.code.ListGitleaksRequest"></a>

### ListGitleaksRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| project_id | [uint32](#uint32) |  |  |
| code_data_source_id | [uint32](#uint32) |  |  |
| gitleaks_id | [uint32](#uint32) |  |  |






<a name="code.code.ListGitleaksResponse"></a>

### ListGitleaksResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| gitleaks | [Gitleaks](#code.code.Gitleaks) | repeated |  |






<a name="code.code.PutEnterpriseOrgRequest"></a>

### PutEnterpriseOrgRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| project_id | [uint32](#uint32) |  |  |
| enterprise_org | [EnterpriseOrgForUpsert](#code.code.EnterpriseOrgForUpsert) |  |  |






<a name="code.code.PutEnterpriseOrgResponse"></a>

### PutEnterpriseOrgResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| enterprise_org | [EnterpriseOrg](#code.code.EnterpriseOrg) |  |  |






<a name="code.code.PutGitleaksRequest"></a>

### PutGitleaksRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| project_id | [uint32](#uint32) |  |  |
| gitleaks | [GitleaksForUpsert](#code.code.GitleaksForUpsert) |  |  |






<a name="code.code.PutGitleaksResponse"></a>

### PutGitleaksResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| gitleaks | [Gitleaks](#code.code.Gitleaks) |  |  |





 

 

 


<a name="code.code.CodeService"></a>

### CodeService


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| ListDataSource | [ListDataSourceRequest](#code.code.ListDataSourceRequest) | [ListDataSourceResponse](#code.code.ListDataSourceResponse) | Code DataSource |
| ListGitleaks | [ListGitleaksRequest](#code.code.ListGitleaksRequest) | [ListGitleaksResponse](#code.code.ListGitleaksResponse) | Gitleaks |
| PutGitleaks | [PutGitleaksRequest](#code.code.PutGitleaksRequest) | [PutGitleaksResponse](#code.code.PutGitleaksResponse) |  |
| DeleteGitleaks | [DeleteGitleaksRequest](#code.code.DeleteGitleaksRequest) | [.google.protobuf.Empty](#google.protobuf.Empty) |  |
| ListEnterpriseOrg | [ListEnterpriseOrgRequest](#code.code.ListEnterpriseOrgRequest) | [ListEnterpriseOrgResponse](#code.code.ListEnterpriseOrgResponse) | Enterprise |
| PutEnterpriseOrg | [PutEnterpriseOrgRequest](#code.code.PutEnterpriseOrgRequest) | [PutEnterpriseOrgResponse](#code.code.PutEnterpriseOrgResponse) |  |
| DeleteEnterpriseOrg | [DeleteEnterpriseOrgRequest](#code.code.DeleteEnterpriseOrgRequest) | [.google.protobuf.Empty](#google.protobuf.Empty) |  |
| InvokeScanGitleaks | [InvokeScanGitleaksRequest](#code.code.InvokeScanGitleaksRequest) | [.google.protobuf.Empty](#google.protobuf.Empty) | Scan

For ondeamnd |
| InvokeScanAllGitleaks | [.google.protobuf.Empty](#google.protobuf.Empty) | [.google.protobuf.Empty](#google.protobuf.Empty) | For scheduled |

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

