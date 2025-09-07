GET http://localhost:8081/api
[Options]
variable: base_url=http://localhost:8081/api
HTTP 200

### ============================================================================
### 1. Verify server is running
### ============================================================================

GET {{base_url}}
HTTP 200
[Captures]
success: jsonpath "$.success"
app_name: jsonpath "$.data.app_name"
[Asserts]
jsonpath "$.success" == true
jsonpath "$.data.app_name" == "RustGuard"


### ============================================================================
### 2. Check the health endpoint
### ============================================================================

GET {{base_url}}/health
HTTP 200
[Captures]
success: jsonpath "$.success"
status: jsonpath "$.data.status"
database_status: jsonpath "$.data.database.status"
fingerprint_status: jsonpath "$.data.fingerprint_store.status"
memory_resident_set_size_kb: jsonpath "$.data.memory_usage.resident_set_size_kb"
memory_virtual_memory_size_kb: jsonpath "$.data.memory_usage.virtual_memory_size_kb"
[Asserts]
jsonpath "$.success" == true
jsonpath "$.data.status" == "healthy"


### ============================================================================
### 3. Check the health detail
### ============================================================================

GET {{base_url}}/health/detail
HTTP 200
[Captures]
success: jsonpath "$.success"
[Asserts]
jsonpath "$.success" == true
