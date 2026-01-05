# KeyCloak Library - Authorization & Authentication Service

License: MIT | Java: 17+ | Spring Boot: 3.x

```
 _____          _____  _                 _
|  |  |___   __|     |(_)___ ___ ___ _ _| |
| -| -| . | / /| | | || / __/ _ \ _ \ '_| |
|_____|___|/_/||____ ||__| |___/___/ |_|_|_|
              |_____|

Easy Authentication & Authorization for Java
```

---

## Table of Contents

- Introduction
- Features
- Project Structure
- System Requirements
- Installation
- Configuration
- Usage
- API Reference
- Error Handling
- Optimization Tips
- Contributing
- Support

---

## Introduction

KeyCloak Library is a comprehensive integration with Keycloak (an open-source Identity and Access Management platform). It provides easy-to-use methods for handling authentication, authorization, user management, and role-based access control in Spring Boot applications.

The library simplifies complex Keycloak REST API calls into simple Java method calls, allowing developers to focus on business logic rather than integration details.

```
YOUR APPLICATION
       |
       | Uses
       v
+------------------+
| KeyCloak Library |
+------------------+
       |
       | Communicates with
       v
+------------------+
|   Keycloak       |
|   Server         |
+------------------+
       |
       | Stores
       v
+------------------+
|   Database      |
+------------------+
```

---

## Features

### Authentication Features
- User login with JWT token generation
- Token refresh functionality
- User logout with token revocation
- Token validation and introspection
- Automatic token expiration handling

### User Management Features
- Register new users
- Search users by ID or username
- Update user profile information
- Enable and disable user accounts
- Reset user passwords (admin operation)
- Change user passwords (user operation)
- Check if user exists

### Role Management Features
- Assign realm roles (global roles)
- Assign client roles (application-scoped roles)
- Remove roles from users
- Retrieve all user roles
- Check user role membership
- Get detailed role information

### Token Management Features
- Decode JWT tokens
- Validate tokens via introspection
- Refresh expired tokens
- Revoke tokens

---

## Project Structure

```
KeyCloakLibrary/
|
+-- authz-core/                               [Core authorization module]                
|   +-- src/main/java/org/ldang/keycloack/
|   |   +-- config/                           [Configuration for RestTemplate]
|   |   |   +-- RestTemplateConfig.java
|   |   |
|   |   +-- Configuration/                    [Configuration classes]
|   |   |   +-- KeyCloakProperties.java
|   |   |   +-- KeyCloakAutoConfiguration.java
|   |   |
|   |   +-- constans/                         [Constants]
|   |   |   +-- AuthzConstans.java
|   |   |   +-- AuthzErrorCode.java
|   |   |
|   |   +-- dto/                              [Data Transfer Objects]     
|   |   |   +-- role/
|   |   |   +-- token/
|   |   |   +-- user/
|   |   |
|   |   +-- exception/                        [Exception handling]
|   |   |   +-- AuthzException.java
|   |   |   +-- GlobalExceptionCustom.java
|   |   |   +-- GlobalExceptionHandler.java
|   |   |
|   |   +-- helper/                           [Helper functions]           
|   |   |   +-- CommonHelpers.java
|   |   |   +-- KCError.java
|   |   |
|   |   +-- service/                          [Service layer]
|   |   |   +-- KeyCloakService.java          [Interface]
|   |   |   +-- KeyCloakServiceImpl.java      [Implementation]
|   |   |
|   |   +-- utils/                            [Utility  classes]        
|   |       +-- KCResponse.java
|   |       +-- TokenDecoder.java
|   |       +-- validation/
|   |
|   +-- pom.xml
|   +-- KEYCLOAK_SERVICE_DOCUMENTATION.md
                      
```

---

## System Requirements

### Required Software
- Java: 17 or higher
- Maven: 3.6.0 or higher
- Spring Boot: 3.x or later
- Keycloak: 26.x (latest stable)

### Optional Software
- Docker: For running Keycloak in containers
- PostgreSQL or MySQL: Database for Keycloak persistence

---

## Installation

### Step 1: Clone Repository

```bash
git clone https://github.com/dangthanhloc0/KeyCloackLibrary.git
```

### Step 2: Build with Maven

```bash
# Build entire project
mvn clean install

# Or build only authz-core
cd KeyCloakLibrary/authz-core
mvn clean install
```

### Step 3: Install Keycloak

#### Option 1: Using Docker (Recommended)

```bash
docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:latest start-dev
```

Access Admin Console: http://localhost:8080/admin

#### Option 2: Download from Keycloak.org

```bash
# Download latest version
wget https://github.com/keycloak/keycloak/releases/download/20.0.0/keycloak-20.0.0.tar.gz

# Extract
tar -xzf keycloak-20.0.0.tar.gz
cd keycloak-20.0.0

# Run
./bin/kc.sh start-dev
```

### Step 4: Setup Keycloak

Access Admin Console at: http://localhost:8080/admin

### Login
- Username: admin
- Password: admin

#### Create a Realm
1. Click on "Manage realms" at the top left
2. Select "Create realm"
![img_2.png](img_2.png)
3. Enter realm name: "your-realm". Ex: **ApplicationRealm**
4. Click "Create"
![img_4.png](img_4.png)

#### Create a Client
1. Click and Navigate to your realm
![img_5.png](img_5.png)
2. Go to "Clients" section
3. Click "Create"
![img_6.png](img_6.png)
4. Fill in:
   - Client ID: "your-client-ID"
   - Client Protocol: "openid-connect"
![img_7.png](img_7.png)
5. Click "Next"

#### Configure Client
6. In the "capability config " tab:
   - Client authentication : ON
   - Authorization: ON
   - Standard Flow Enabled: ON
   - Direct Access Grants Enabled: ON
![img_8.png](img_8.png)
7. Click "Next".
8. Fill in:
    - Root URL: ${authBaseUrl}
    - Home URL: /realms/{your-Realm}/{your-client-ID}/
    - Valid redirect URIs: /realms/{your-Realm}/{your-client-ID}/*
![img_9.png](img_9.png)
9. Click "Save"

### Client ID
10. Go to "Clients" > "your-client-ID"
11. In the "Credentials" tab: Copy the "Client Secret"
![img_10.png](img_10.png)
---

## Configuration

### Method 1: Using application.properties

Create or update `application.properties` in your Spring Boot application:

```properties
# Keycloak Server Configuration
keycloak.domainUrl=http://localhost:8080
keycloak.realmName={your-realm}
keycloak.clientSecret={your-client-secret}
keycloak.clientId={your-client-ID}
# Admin Credentials for API Operations
keycloak.adminUsername=admin
keycloak.adminPassword=admin
```

### Method 2: Using application.yml

```yaml
# Keycloak Server Configuration
keycloak:
  domainUrl: http://localhost:8080
  realmName: your-realm
  clientId: your-client-ID
  clientSecret: your-client-secret

  # Admin Credentials for API Operations
  adminUsername: admin
  adminPassword: admin
```

### Method 3: Using in your Project

```pom.xml
Add dependency to your pom.xml:
  <dependency>
      <groupId>org.ldang.keycloack</groupId>
      <artifactId>authz-core</artifactId>
      <version>1.0-SNAPSHOT</version>
      <scope>compile</scope>
  </dependency>
```

---

## Usage Guide

### Step 1: Inject the Service

```java
@Service
public class AuthenticationService {
    
    @Autowired
    private KeyCloakService keycloakService;
    
    // Your service methods here
}
```

### Example 1: User Login

```
STEP 1: Client sends login request
    |
    v
CLIENT ----[POST /login]----> YOUR APPLICATION
    |                              |
    |                              | Calls keycloakService.login()
    |                              v
    |                         KEYCLOAK SERVER
    |                              |
    |<----[access_token]---------- +
    |<----[refresh_token]--------- +
```

```java
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest request) {
    KCResponse<TokenResponse> response = 
        keycloakService.login(request.getUsername(), request.getPassword());
    
    if (response.isSuccess()) {
        return ResponseEntity.ok(response.getData());
    }
    
    // Handle error
    return ResponseEntity
        .status(HttpStatus.UNAUTHORIZED)
        .body(response.getError());
}
```

Response example:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Example 2: User Registration

```java
@PostMapping("/register")
public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
    // Register user and assign "user" role
    KCResponse<UserInformation> response = 
        keycloakService.register(request, "user");
    
    if (response.isSuccess()) {
        return ResponseEntity.status(HttpStatus.CREATED).body(response.getData());
    }
    
    return ResponseEntity
        .status(HttpStatus.BAD_REQUEST)
        .body(response.getError());
}
```

Request example:
```json
{
  "userName": "john.doe",
  "email": "john@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "password": "SecurePass123!"
}
```

### Example 3: Token Refresh

```
TOKEN EXPIRES
    |
    v
CLIENT has old token
    |
    v
CLIENT sends refresh request with refresh_token
    |
    v
YOUR APPLICATION ----[refresh_token]----> KEYCLOAK
    |                                           |
    |<--------[new access_token]------------- +
    |
    v
CLIENT stores new token and continues
```

```java
@PostMapping("/refresh-token")
public ResponseEntity<?> refreshToken(@RequestBody TokenRefreshRequest request) {
    KCResponse<TokenResponse> response = 
        keycloakService.refreshToken(request.getRefreshToken());
    
    if (response.isSuccess()) {
        return ResponseEntity.ok(response.getData());
    }
    
    return ResponseEntity
        .status(HttpStatus.UNAUTHORIZED)
        .body(response.getError());
}
```

### Example 4: Token Validation

```java
@PostMapping("/validate-token")
public ResponseEntity<?> validateToken(
        @RequestHeader("Authorization") String bearerToken) {
    
    // Extract token from "Bearer <token>"
    String token = bearerToken.substring("Bearer ".length());
    
    TokenIntrospectionResponse tokenInfo = keycloakService.introspectToken(token);
    
    if (!tokenInfo.getActive()) {
        return ResponseEntity
            .status(HttpStatus.UNAUTHORIZED)
            .body("Token is invalid or expired");
    }
    
    return ResponseEntity.ok(tokenInfo);
}
```

### Example 5: Role-Based Access Control

```
USER makes request to PROTECTED ENDPOINT
    |
    v
APPLICATION checks token
    |
    +---> Token valid?
    |       Yes: Continue
    |       No: Return 401
    |
    v
APPLICATION checks user role
    |
    +---> User has admin role?
    |       Yes: Grant access
    |       No: Return 403
    |
    v
ENDPOINT executes
```

```java
@PostMapping("/admin-only")
public ResponseEntity<?> adminOnlyEndpoint(
        @RequestHeader("Authorization") String bearerToken) {
    
    String token = bearerToken.substring("Bearer ".length());
    TokenIntrospectionResponse tokenInfo = keycloakService.introspectToken(token);
    
    if (!tokenInfo.getActive()) {
        return ResponseEntity
            .status(HttpStatus.UNAUTHORIZED)
            .body("Token invalid");
    }
    
    String userId = tokenInfo.getSubject();
    
    // Check if user has admin role
    if (keycloakService.userHasRealmRole(userId, "admin")) {
        return ResponseEntity.ok("You have admin access");
    }
    
    return ResponseEntity
        .status(HttpStatus.FORBIDDEN)
        .body("You do not have permission");
}
```

### Example 6: User Management

```java
@Service
public class UserManagementService {
    
    @Autowired
    private KeyCloakService keycloakService;
    
    // Get user information
    public UserInformation getUser(String userId) {
        KCResponse<UserInformation> response = 
            keycloakService.getUserById(userId);
        
        if (response.isSuccess()) {
            return response.getData();
        }
        throw new UserNotFoundException("User not found");
    }
    
    // Update user
    public UserInformation updateUser(String userId, UpdateUserRequest request) {
        KCResponse<UserInformation> response = 
            keycloakService.updateUserByUserId(userId, request);
        
        if (response.isSuccess()) {
            return response.getData();
        }
        throw new RuntimeException("Update failed");
    }
    
    // Assign role to user
    public void assignAdminRole(String userId) {
        KCResponse<UserInformation> response = 
            keycloakService.assignRealmRole(userId, "admin");
        
        if (!response.isSuccess()) {
            throw new RuntimeException("Failed to assign role");
        }
    }
    
    // Disable user
    public void disableUser(String userId) {
        keycloakService.disableUserByUserId(userId);
    }
    
    // Get all user roles
    public RoleResponse getUserRoles(String userId) {
        KCResponse<RoleResponse> response = 
            keycloakService.getAllRolesOfUser(userId);
        
        if (response.isSuccess()) {
            return response.getData();
        }
        return null;
    }
}
```

---

## API Reference

### Authentication Methods

Available methods for user authentication:

| Method | Signature | Purpose |
|--------|-----------|---------|
| login | login(String userName, String password) | Authenticate user and get tokens |
| refreshToken | refreshToken(String refreshToken) | Get new access token |
| logout | logout(String refreshToken) | Revoke refresh token |
| introspectToken | introspectToken(String token) | Validate and get token information |
| decodeToken | decodeToken(String token) | Decode JWT without validation |

### User Management Methods

| Method | Signature | Purpose |
|--------|-----------|---------|
| register | register(RegisterRequest req) | Create new user |
| register | register(RegisterRequest req, String role) | Create user with role |
| getUserById | getUserById(String userId) | Get user by ID |
| getUserByUsername | getUserByUsername(String userName) | Get user by username |
| updateUserByUserId | updateUserByUserId(String userId, UpdateUserRequest req) | Update user profile |
| updateUserByUserName | updateUserByUserName(String userName, UpdateUserRequest req) | Update user by username |
| enableUserByUserId | enableUserByUserId(String userId) | Enable user account |
| disableUserByUserId | disableUserByUserId(String userId) | Disable user account |
| enableUserByUserName | enableUserByUserName(String userName) | Enable user by username |
| disableUserByUserName | disableUserByUserName(String userName) | Disable user by username |
| resetPassword | resetPassword(String userId, String newPassword, boolean temporary) | Reset user password |
| changePassword | changePassword(String userName, String oldPassword, String newPassword) | User changes own password |
| isUserExist | isUserExist(String userId) | Check if user exists |

### Role Management Methods

| Method | Signature | Purpose |
|--------|-----------|---------|
| assignRealmRole | assignRealmRole(String userId, String roleName) | Assign global role |
| assignClientRole | assignClientRole(String userId, String roleName) | Assign application role |
| removeRealmRoleFromUser | removeRealmRoleFromUser(String userId, String roleName) | Remove global role |
| removeClientRoleFromUser | removeClientRoleFromUser(String userId, String roleName) | Remove application role |
| getAllRolesOfUser | getAllRolesOfUser(String userId) | Get all user roles |
| getRealmRolesOfUser | getRealmRolesOfUser(String userId, String token) | Get global roles |
| getClientRolesOfUser | getClientRolesOfUser(String userId, String token) | Get application roles |
| userHasRealmRole | userHasRealmRole(String userId, String roleName) | Check global role |
| userHasClientRole | userHasClientRole(String userId, String roleName) | Check application role |
| getRealmRoleData | getRealmRoleData(String roleName, String token) | Get role details |

---

## Error Handling

### Common Error Codes

| Error Code | HTTP Status | Description |
|-----------|------------|-------------|
| INVALID_USER_NAME_OR_PASSWORD | 401 | Username or password is incorrect |
| USER_NOT_FOUND | 404 | User does not exist |
| NOT_FOUND_REALM_ROLE | 404 | Global role does not exist |
| CLIENT_ROLE_NOT_FOUND | 404 | Application role does not exist |
| TOKEN_INVALID | 401 | Token is invalid or expired |
| VALIDATION_ERROR | 400 | Input validation failed |
| DUPLICATE | 409 | Duplicate username or email |
| FORBIDDEN | 403 | Access denied |
| UNAUTHORIZED | 401 | Authentication failed |
| KEYCLOAK_SERVER_ERROR | 500 | Keycloak server error |
| KEYCLOAK_CONNECTION_ERROR | 503 | Cannot connect to Keycloak |
| UNKNOWN_ERROR | 500 | Unknown error occurred |

### Check Response Status

Always check if response is successful before using data:

```java
KCResponse<UserInformation> response = keycloakService.getUserById(userId);

if (response.isSuccess()) {
    UserInformation user = response.getData();
    System.out.println("User: " + user.getUsername());
} else {
    String errorCode = response.getError().getCode();
    String errorMessage = response.getError().getMessage();
    System.err.println("Error: " + errorCode + " - " + errorMessage);
}
```

---


## Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch: git checkout -b feature/YourFeature
3. Make your changes and commit: git commit -m 'Add YourFeature'
4. Push to the branch: git push origin feature/YourFeature
5. Open a Pull Request

---

## Support and Documentation

For detailed information about each method, see: KEYCLOAK_SERVICE_DOCUMENTATION.md

For Keycloak documentation: https://www.keycloak.org/documentation

For Spring Security documentation: https://spring.io/projects/spring-security

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

## Version Information

Version: 1.0.0
Last Updated: December 28, 2025
Java Compatibility: 17+
Spring Boot Compatibility: 3.x+
```


Authored by: Dang Thanh Loc
contact: 
 - Email: dangthanhloca2@gmail.com
 - Phone: +84 379001285
 - Fb: https://www.facebook.com/angloc.149807/