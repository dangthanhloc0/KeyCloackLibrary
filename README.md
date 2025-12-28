# KeyCloak Library - Authorization & Authentication Service

License: MIT | Java: 11+ | Spring Boot: 2.x

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
KeyCloakLibary/
├── authz-core/                          [Core authorization module]
│   ├── src/main/java/org/ldang/keycloack/
│   │   ├── Configuration/              [Configuration classes]
│   │   │   └── KeyCloakProperties.java
│   │   ├── constans/                   [Constants]
│   │   │   ├── AuthzConstans.java
│   │   │   └── AuthzErrorCode.java
│   │   ├── dto/                        [Data Transfer Objects]
│   │   │   ├── role/
│   │   │   ├── token/
│   │   │   └── user/
│   │   ├── exception/                  [Exception handling]
│   │   │   └── GlobalExceptionCustom.java
│   │   ├── helper/                     [Helper functions]
│   │   │   └── CommonHelpers.java
│   │   ├── service/                    [Service layer]
│   │   │   ├── KeyCloakService.java    [Interface]
│   │   │   └── KeyCloakServiceImpl.java [Implementation]
│   │   └── utils/                      [Utilities]
│   │       ├── KCResponse.java
│   │       ├── TokenDecoder.java
│   │       └── validation/
│   ├── pom.xml
│   └── KEYCLOAK_SERVICE_DOCUMENTATION.md
│
├── AuthenticaitonService/               [Authentication microservice]
│   ├── src/main/java/com/ldang/auth/
│   ├── resources/
│   │   └── application.properties
│   └── pom.xml
│
├── commonUtils/                         [Shared utilities]
├── configation/                         [Configuration module]
├── api-gatewave/                        [API Gateway]
├── OrderService/                        [Order management microservice]
├── paymentService/                      [Payment microservice]
├── productService/                      [Product microservice]
├── StockService/                        [Inventory microservice]
├── userService/                         [User microservice]
├── TaoRung/                             [Demo application]
└── README.md                            [This file]
```

---

## System Requirements

### Required Software
- Java: 11 or higher
- Maven: 3.6.0 or higher
- Spring Boot: 2.x or later
- Keycloak: 12.0 or later

### Optional Software
- Docker: For running Keycloak in containers
- PostgreSQL or MySQL: Database for Keycloak persistence

---

## Installation

### Step 1: Clone Repository

```bash
git clone <repository-url>
cd sourceTraining
```

### Step 2: Build with Maven

```bash
# Build entire project
mvn clean install

# Or build only authz-core
cd KeyCloakLibary/authz-core
mvn clean install
```

### Step 3: Install Keycloak

#### Option 1: Using Docker (Recommended)

```bash
docker run -d \
  --name keycloak \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest \
  start-dev
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

#### Create a Realm
1. Click on "Master" at the top left
2. Select "Create realm"
3. Enter realm name: "my-realm"
4. Click "Create"

#### Create a Client
1. Navigate to your realm
2. Go to "Clients" section
3. Click "Create"
4. Fill in:
   - Client ID: "my-client"
   - Client Protocol: "openid-connect"
5. Click "Save"

#### Configure Client
1. Go to "Clients" > "my-client"
2. In the "Settings" tab:
   - Access Type: "confidential"
   - Standard Flow Enabled: ON
   - Direct Access Grants Enabled: ON
3. In the "Credentials" tab: Copy the "Client Secret"

#### Create a Test User
1. Go to "Users" section
2. Click "Add user"
3. Fill in user information
4. Go to "Credentials" tab
5. Set a password

---

## Configuration

### Method 1: Using application.properties

Create or update `application.properties` in your Spring Boot application:

```properties
# Keycloak Server Configuration
keycloak.domain-url=http://localhost:8080/auth
keycloak.realm-name=my-realm
keycloak.client-id=my-client
keycloak.client-secret=YOUR_CLIENT_SECRET_HERE

# Admin Credentials for API Operations
keycloak.admin-username=admin
keycloak.admin-password=admin

# Application Server
server.port=8081
```

### Method 2: Using application.yml

```yaml
keycloak:
  domain-url: http://localhost:8080/auth
  realm-name: my-realm
  client-id: my-client
  client-secret: YOUR_CLIENT_SECRET_HERE
  admin-username: admin
  admin-password: admin

server:
  port: 8081
```

### Method 3: Java Configuration

```java
@Configuration
public class KeyCloakConfig {
    
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
    
    @Bean
    public KeyCloakService keyCloakService(
            KeyCloakProperties props,
            RestTemplate restTemplate,
            TokenDecoder tokenDecoder) {
        return new KeyCloakServiceImpl(props, restTemplate, tokenDecoder);
    }
}
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

### Handling Errors in Your Code

```java
@ExceptionHandler(AuthzException.class)
public ResponseEntity<?> handleAuthzException(AuthzException ex) {
    Map<String, Object> errorResponse = new HashMap<>();
    errorResponse.put("error_code", ex.getErrorCode());
    errorResponse.put("error_message", ex.getMessage());
    errorResponse.put("timestamp", LocalDateTime.now());
    
    HttpStatus status = getHttpStatusForErrorCode(ex.getErrorCode());
    
    return ResponseEntity.status(status).body(errorResponse);
}

private HttpStatus getHttpStatusForErrorCode(String code) {
    switch(code) {
        case "INVALID_USER_NAME_OR_PASSWORD":
            return HttpStatus.UNAUTHORIZED;
        case "USER_NOT_FOUND":
            return HttpStatus.NOT_FOUND;
        case "VALIDATION_ERROR":
        case "DUPLICATE":
            return HttpStatus.BAD_REQUEST;
        case "FORBIDDEN":
            return HttpStatus.FORBIDDEN;
        default:
            return HttpStatus.INTERNAL_SERVER_ERROR;
    }
}
```

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

## Optimization Tips

### 1. Cache User Roles

Avoid repeated role lookups by caching:

```java
@Cacheable(value = "userRoles", key = "#userId")
public RoleResponse getUserRoles(String userId) {
    return keycloakService.getAllRolesOfUser(userId).getData();
}

// Invalidate cache when roles change
@CacheEvict(value = "userRoles", key = "#userId")
public void invalidateUserRoleCache(String userId) {
}
```

### 2. Use Async Operations

For non-critical operations, use async processing:

```java
@Async
public CompletableFuture<UserInformation> registerUserAsync(RegisterRequest req) {
    KCResponse<UserInformation> response = 
        keycloakService.register(req, "user");
    
    if (response.isSuccess()) {
        return CompletableFuture.completedFuture(response.getData());
    }
    
    return CompletableFuture.failedFuture(
        new RuntimeException("Registration failed")
    );
}
```

### 3. Configure Connection Timeouts

```java
@Bean
public RestTemplate restTemplate() {
    HttpComponentsClientHttpRequestFactory factory = 
        new HttpComponentsClientHttpRequestFactory();
    
    // Set timeouts (in milliseconds)
    factory.setConnectTimeout(5000);    // 5 seconds
    factory.setReadTimeout(10000);      // 10 seconds
    
    return new RestTemplate(factory);
}
```

### 4. Batch Operations

When assigning multiple roles, do it sequentially with proper error handling:

```java
public void assignMultipleRoles(String userId, List<String> roleNames) {
    for (String roleName : roleNames) {
        try {
            keycloakService.assignRealmRole(userId, roleName);
        } catch (Exception e) {
            log.error("Failed to assign role: " + roleName, e);
        }
    }
}
```

### 5. Log Important Events

```java
@Service
public class AuditService {
    
    @Autowired
    private Logger logger;
    
    public void logUserLogin(String username, boolean success) {
        if (success) {
            logger.info("User logged in: " + username);
        } else {
            logger.warn("Failed login attempt: " + username);
        }
    }
    
    public void logRoleAssignment(String userId, String roleName) {
        logger.info("Role assigned - User: " + userId + ", Role: " + roleName);
    }
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
Java Compatibility: 11+
Spring Boot Compatibility: 2.x+

