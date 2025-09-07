GET http://localhost:8081/api
[Options]
variable: base_url=http://localhost:8081/api
HTTP 200

### ============================================================================
### 1. Register User with Role 'user' (default)
### ============================================================================

POST {{base_url}}/register
Content-Type: application/json
{
    "email": "user@test.com",
    "password": "TestPassword123!",
    "first_name": "Test",
    "last_name": "User",
    "username": "testuser",
    "role": "user"
}
HTTP 201
[Captures]
user_success: jsonpath "$.success"
user_id: jsonpath "$.data.id"
user_role: jsonpath "$.data.role"
[Asserts]
jsonpath "$.success" == true
jsonpath "$.data.role" == "user"

### ============================================================================
### 2. Register User with Role 'admin'
### ============================================================================

POST {{base_url}}/register
Content-Type: application/json
{
    "email": "admin@test.com",
    "password": "TestPassword123!",
    "first_name": "Test",
    "last_name": "Admin",
    "username": "testadmin",
    "role": "admin"
}
HTTP 201
[Captures]
admin_success: jsonpath "$.success"
admin_id: jsonpath "$.data.id"
admin_role: jsonpath "$.data.role"
[Asserts]
jsonpath "$.success" == true
jsonpath "$.data.role" == "admin"

### ============================================================================
### 3. Register User with Role 'root'
### ============================================================================

POST {{base_url}}/register
Content-Type: application/json
{
    "email": "root@test.com",
    "password": "TestPassword123!",
    "first_name": "Test",
    "last_name": "Root",
    "username": "testroot",
    "role": "root"
}
HTTP 201
[Captures]
root_success: jsonpath "$.success"
root_id: jsonpath "$.data.id"
root_role: jsonpath "$.data.role"
[Asserts]
jsonpath "$.success" == true
jsonpath "$.data.role" == "root"