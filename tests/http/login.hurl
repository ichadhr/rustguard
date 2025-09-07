GET http://localhost:8081/api
[Options]
variable: base_url=http://localhost:8081/api
HTTP 200

### ============================================================================
### 1. Login with User Role
### ============================================================================

POST {{base_url}}/auth
Content-Type: application/json
{
    "email": "user@test.com",
    "password": "TestPassword123!"
}
HTTP 200
[Captures]
user_login_success: jsonpath "$.success"
user_token: jsonpath "$.data.token"
user_refresh_token: jsonpath "$.data.refresh_token"
user_fingerprint: cookie "recog"
[Asserts]
jsonpath "$.success" == true
jsonpath "$.data.token" isString
jsonpath "$.data.refresh_token" isString
cookie "recog" exists

### ============================================================================
### 2. Test /profile with User Role
### ============================================================================

GET {{base_url}}/profile
Authorization: Bearer {{user_token}}
Cookie: recog={{user_fingerprint}}
HTTP 200
[Asserts]
jsonpath "$.success" == true
jsonpath "$.data.email" == "user@test.com"
jsonpath "$.data.role" == "user"

### ============================================================================
### 3. Login with Admin Role
### ============================================================================

POST {{base_url}}/auth
Content-Type: application/json
{
    "email": "admin@test.com",
    "password": "TestPassword123!"
}
HTTP 200
[Captures]
admin_login_success: jsonpath "$.success"
admin_token: jsonpath "$.data.token"
admin_refresh_token: jsonpath "$.data.refresh_token"
admin_fingerprint: cookie "recog"
[Asserts]
jsonpath "$.success" == true
jsonpath "$.data.token" isString
jsonpath "$.data.refresh_token" isString
cookie "recog" exists

### ============================================================================
### 4. Test /profile with Admin Role
### ============================================================================

GET {{base_url}}/profile
Authorization: Bearer {{admin_token}}
Cookie: recog={{admin_fingerprint}}
HTTP 200
[Asserts]
jsonpath "$.success" == true
jsonpath "$.data.email" == "admin@test.com"
jsonpath "$.data.role" == "admin"

### ============================================================================
### 5. Login with Root Role
### ============================================================================

POST {{base_url}}/auth
Content-Type: application/json
{
    "email": "root@test.com",
    "password": "TestPassword123!"
}
HTTP 200
[Captures]
root_login_success: jsonpath "$.success"
root_token: jsonpath "$.data.token"
root_refresh_token: jsonpath "$.data.refresh_token"
root_fingerprint: cookie "recog"
[Asserts]
jsonpath "$.success" == true
jsonpath "$.data.token" isString
jsonpath "$.data.refresh_token" isString
cookie "recog" exists

### ============================================================================
### 6. Test /profile with Root Role
### ============================================================================

GET {{base_url}}/profile
Authorization: Bearer {{root_token}}
Cookie: recog={{root_fingerprint}}
HTTP 200
[Asserts]
jsonpath "$.success" == true
jsonpath "$.data.email" == "root@test.com"
jsonpath "$.data.role" == "root"