# KeyCloakService Documentation

## Overview
The `KeyCloakService` interface provides a comprehensive set of methods for interacting with Keycloak, an open-source Identity and Access Management (IAM) system. This service handles user management, role assignment, token operations, and user authentication.

## Service Methods

### 1. **Authentication Methods**

#### `login(String userName, String password): KCResponse<TokenResponse>`
Authenticates a user and returns JWT tokens (access and refresh tokens).

**Business Logic:**
- Sends username and password credentials to Keycloak's token endpoint
- Uses OAuth2 password grant flow with configured client credentials
- Returns `TokenResponse` containing:
  - `access_token`: JWT token for API access
  - `refresh_token`: Token for refreshing the access token
  - `expires_in`: Token expiration time in seconds
  - `token_type`: Usually "Bearer"

**Error Handling:**
- **Invalid Credentials (401)**: Returns `INVALID_USER_NAME_OR_PASSWORD` error
- **Username Not Found**: Returns `USER_NOT_FOUND` error
- **Validation Errors**: Returns `VALIDATION_ERROR` with error details

**Example:**
```java
KCResponse<TokenResponse> response = keycloakService.login("john.doe", "password123");
if (response.isSuccess()) {
    String accessToken = response.getData().getAccessToken();
    // Use accessToken for subsequent API calls
}
```

---

#### `refreshToken(String refreshToken): KCResponse<TokenResponse>`
Refreshes an expired or expiring access token using a valid refresh token.

**Business Logic:**
- Uses refresh token to obtain new access and refresh tokens
- Maintains user session without requiring password re-entry
- Implements OAuth2 refresh token grant flow

**Error Handling:**
- **Invalid/Expired Refresh Token**: Returns `TOKEN_INVALID` error
- **Token Expired**: Token cannot be refreshed if too old

**Example:**
```java
KCResponse<TokenResponse> newTokens = keycloakService.refreshToken(oldRefreshToken);
```

---

#### `logout(String refreshToken): KCResponse<?>`
Revokes a refresh token, effectively logging out the user.

**Business Logic:**
- Invalidates the provided refresh token on the Keycloak server
- Prevents further token refresh operations
- Clears user session

**Error Handling:**
- **Invalid Token**: Returns `TOKEN_INVALID` error
- **Already Revoked**: Returns `TOKEN_INVALID` error

**Example:**
```java
keycloakService.logout(userRefreshToken);
```

---

### 2. **User Management Methods**

#### `register(RegisterRequest req): KCResponse<UserInformation>`
Registers a new user in Keycloak without assigning any roles.

**Business Logic:**
- Validates all required fields: username, email, firstName, lastName, password
- Creates user account in Keycloak with provided details
- Automatically enables the user and marks email as verified
- Sets password as non-temporary (user can log in immediately)
- Retrieves and returns complete user information with empty role lists

**Input Validation:**
- `userName`: Required, unique across realm
- `email`: Required, valid email format, unique
- `firstName`: Required, non-empty
- `lastName`: Required, non-empty
- `password`: Required, must meet realm password policy

**Error Handling:**
- **Duplicate Username/Email**: Returns `VALIDATION_ERROR` with conflict message
- **Invalid Input**: Returns `VALIDATION_ERROR` with field-level errors
- **Registration Failure**: Returns `UNKNOWN_ERROR`

**Example:**
```java
RegisterRequest req = new RegisterRequest();
req.setUserName("john.doe");
req.setEmail("john@example.com");
req.setFirstName("John");
req.setLastName("Doe");
req.setPassword("SecurePass123!");

KCResponse<UserInformation> response = keycloakService.register(req);
```

---

#### `register(RegisterRequest req, String role): KCResponse<UserInformation>`
Registers a new user and immediately assigns them a realm role.

**Business Logic:**
- Performs same registration as `register(RegisterRequest req)`
- After user creation, automatically assigns the specified realm role
- Returns updated user information with assigned role in realm roles list

**Error Handling:**
- **User registration fails**: Returns user registration error
- **Role assignment fails**: Registration succeeds but role assignment error is thrown
- **Invalid Role**: Returns `NOT_FOUND_REALM_ROLE` error

**Example:**
```java
KCResponse<UserInformation> response = keycloakService.register(req, "admin");
// User is created with "admin" realm role
```

---

#### `getUserById(String userId): KCResponse<UserInformation>`
Retrieves complete user information by userId.

**Business Logic:**
- Fetches user profile from Keycloak admin API
- Retrieves all realm roles assigned to user
- Retrieves all client roles organized by client name
- Returns comprehensive `UserInformation` object with:
  - Basic info: id, username, email, firstName, lastName, enabled status
  - Realm roles list
  - Client roles map (clientName -> list of roles)

**Error Handling:**
- **User Not Found (404)**: Returns `USER_NOT_FOUND` error
- **Unauthorized (401)**: Refreshes admin token and retries
- **API Error**: Returns `UNKNOWN_ERROR`

**Example:**
```java
KCResponse<UserInformation> response = keycloakService.getUserById("user-uuid-123");
if (response.isSuccess()) {
    UserInformation user = response.getData();
    List<String> realmRoles = user.getRealmRoles();
    Map<String, List<String>> clientRoles = user.getClientRoles();
}
```

---

#### `getUserByUsername(String userName): KCResponse<UserInformation>`
Retrieves complete user information by username.

**Business Logic:**
- Queries user by username with exact match requirement
- Performs same role retrieval as `getUserById()`
- Returns user with both realm and client roles populated

**Error Handling:**
- **User Not Found**: Returns `USER_NOT_FOUND` error
- **API Error**: Returns error with details

**Example:**
```java
KCResponse<UserInformation> response = keycloakService.getUserByUsername("john.doe");
```

---

#### `updateUserByUserId(String userId, UpdateUserRequest req): KCResponse<UserInformation>`
Updates user profile information by userId.

**Business Logic:**
- Sends PUT request to update user attributes
- Supports updating: firstName, lastName, email, enabled status, etc.
- Returns updated user information with roles

**Error Handling:**
- **User Not Found (404)**: Returns `USER_NOT_FOUND` error
- **Duplicate Email (409)**: Returns `DUPLICATE` error
- **Validation Error**: Returns `UNKNOWN_ERROR`

**Example:**
```java
UpdateUserRequest req = new UpdateUserRequest();
req.setFirstName("Jonathan");
req.setEmail("jonathan@example.com");

KCResponse<UserInformation> response = keycloakService.updateUserByUserId(userId, req);
```

---

#### `updateUserByUserName(String userName, UpdateUserRequest req): KCResponse<UserInformation>`
Updates user profile information by username.

**Business Logic:**
- Looks up user by username
- Performs same update as `updateUserByUserId()`
- Returns updated user information

**Error Handling:**
- **User Not Found**: Returns `USER_NOT_FOUND` error
- **Duplicate Email (409)**: Returns `DUPLICATE` error
- **Validation Error**: Returns errors list

---

#### `enableUserByUserId(String userId): KCResponse<UserInformation>`
Enables a user account by userId.

**Business Logic:**
- Creates `UpdateUserRequest` with `enabled=true`
- Calls `updateUserByUserId()` with this request
- User can now log in (if not disabled for other reasons)

**Error Handling:**
- **User Not Found (404)**: Returns `USER_NOT_FOUND` error

---

#### `disableUserByUserId(String userId): KCResponse<UserInformation>`
Disables a user account by userId.

**Business Logic:**
- Creates `UpdateUserRequest` with `enabled=false`
- Prevents user from logging in
- Existing tokens remain valid until expiration (token introspection still succeeds)

---

#### `enableUserByUserName(String userName): KCResponse<UserInformation>`
Enables a user account by username.

---

#### `disableUserByUserName(String userName): KCResponse<UserInformation>`
Disables a user account by username.

---

#### `resetPassword(String userId, String newPassword, boolean temporary): KCResponse<?>`
Resets user password (admin operation).

**Business Logic:**
- Requires admin privileges
- Directly sets new password without validating old password
- If `temporary=true`: User must change password on next login
- If `temporary=false`: Password is immediately usable

**Error Handling:**
- **User Not Found (404)**: Returns `USER_NOT_FOUND` error
- **Password Policy Violation**: Returns error from Keycloak
- **Permission Denied**: Returns authorization error

**Example:**
```java
keycloakService.resetPassword(userId, "NewSecurePass123!", false);
```

---

#### `changePassword(String userName, String oldPassword, String newPassword): KCResponse<?>`
Allows user to change their own password (requires old password verification).

**Business Logic:**
- Validates old password by attempting login
- If login succeeds, extracts userId from token
- Calls `resetPassword()` with temporary=false
- More secure than admin password reset

**Error Handling:**
- **Invalid Old Password**: Login fails, returns `INVALID_USER_NAME_OR_PASSWORD`
- **User Not Found**: Returns `USER_NOT_FOUND` error

**Example:**
```java
keycloakService.changePassword("john.doe", "OldPass123", "NewPass456");
```

---

### 3. **Role Management Methods**

#### `assignRealmRole(String userId, String roleName): KCResponse<UserInformation>`
Assigns a realm-level role to a user.

**Business Logic:**
- Retrieves realm role data by name
- Maps role to user via Keycloak admin API
- Realm roles are global, apply across entire realm
- Not limited to specific clients

**Error Handling:**
- **Role Not Found**: Returns `NOT_FOUND_REALM_ROLE` error
- **User Not Found**: Returns `USER_NOT_FOUND` error
- **Already Assigned**: Keycloak allows multiple assignments; role is added

**Example:**
```java
keycloakService.assignRealmRole(userId, "admin");
```

---

#### `assignClientRole(String userId, String roleName): KCResponse<UserInformation>`
Assigns a client-specific role to a user.

**Business Logic:**
- Retrieves configured client UUID
- Fetches specific client role by name
- Maps client role to user
- Client roles are scoped to specific client application
- Not visible to other clients in realm

**Error Handling:**
- **Client Role Not Found**: Returns `CLIENT_ROLE_NOT_FOUND` error
- **User Not Found**: Returns `USER_NOT_FOUND` error
- **Client Not Found**: Returns `CLIENT_NOT_FOUND` error

**Example:**
```java
keycloakService.assignClientRole(userId, "user-admin");
```

---

#### `removeRealmRoleFromUser(String userId, String roleName): KCResponse<UserInformation>`
Removes a realm role from a user.

**Business Logic:**
- Retrieves realm role definition
- Sends DELETE request to unmap role
- User no longer has role access
- Returns updated user with role removed

**Error Handling:**
- **Role Not Found**: Returns `NOT_FOUND_REALM_ROLE` error
- **User Not Found**: Returns `USER_NOT_FOUND` error
- **Role Not Assigned**: Keycloak gracefully handles (no error typically)

---

#### `removeClientRoleFromUser(String userId, String roleName): KCResponse<UserInformation>`
Removes a client role from a user.

**Business Logic:**
- Retrieves configured client UUID
- Fetches client role definition
- Sends DELETE request to unmap client role
- Returns updated user with role removed from client roles

**Error Handling:**
- **Role Not Found**: Returns `ROLE_NOT_FOUND` error
- **User Not Found**: Returns `USER_NOT_FOUND` error

---

#### `getAllRolesOfUser(String userId): KCResponse<RoleResponse>`
Retrieves both realm and client roles for a user.

**Business Logic:**
- Validates user exists
- Retrieves realm roles list
- Retrieves client roles map
- Returns `RoleResponse` containing:
  - `realmRoles`: List of realm role names
  - `clientRoles`: Map of clientName -> list of role names

**Error Handling:**
- **User Not Found**: Returns `USER_NOT_FOUND` error
- **API Error**: Returns `TOKEN_INVALID` error

**Example:**
```java
KCResponse<RoleResponse> response = keycloakService.getAllRolesOfUser(userId);
RoleResponse roles = response.getData();
List<String> realmRoles = roles.getRealmRoles();
Map<String, List<String>> clientRoles = roles.getClientRoles();
```

---

#### `getRealmRolesOfUser(String userId, String token): List<String>`
Returns list of realm role names for a user.

**Business Logic:**
- Lower-level method used internally
- Queries Keycloak admin API directly
- Extracts "name" from each role
- Returns empty list if no roles assigned

**Parameters:**
- `userId`: User UUID
- `token`: Admin access token for authorization

---

#### `getClientRolesOfUser(String userId, String token): Map<String, List<String>>`
Returns map of client roles for a user.

**Business Logic:**
- Iterates through all clients in realm
- For each client, retrieves roles assigned to user
- Only includes clients where user has at least one role
- Returns empty map if no client roles

**Returns:**
- `Map<String, List<String>>`: Keys are client names (clientId), values are role lists

---

#### `userHasRealmRole(String userId, String roleName): boolean`
Checks if user has a specific realm role.

**Business Logic:**
- Retrieves all realm roles for user
- Uses stream to find matching role name (case-sensitive)
- Returns boolean (no exception thrown on error)
- Returns false if any API error occurs

**Example:**
```java
boolean isAdmin = keycloakService.userHasRealmRole(userId, "admin");
```

---

#### `userHasClientRole(String userId, String roleName): boolean`
Checks if user has a specific client role.

**Business Logic:**
- Retrieves configured client UUID
- Queries client roles for user
- Checks if role name matches (case-sensitive)
- Returns boolean (no exception thrown on error)

---

#### `getRealmRoleData(String roleName, String token): KCResponse<RealmRoleResponse>`
Retrieves detailed information about a realm role.

**Business Logic:**
- Queries Keycloak admin API by role name
- Returns complete role metadata
- Requires admin privileges

**Returns:**
- `RealmRoleResponse` containing:
  - Role ID
  - Role name
  - Role description
  - Composite role info
  - Attributes

**Error Handling:**
- **Role Not Found (404)**: Returns `NOT_FOUND_REALM_ROLE` error
- **Permission Denied (403)**: Returns `FORBIDDEN` error
- **Unauthorized (401)**: Returns `UNAUTHORIZED` error

---

### 4. **Token Operations**

#### `introspectToken(String accessToken): TokenIntrospectionResponse`
Validates and inspects an access token to retrieve user information.

**Business Logic:**
- Sends token to Keycloak's token introspection endpoint
- Returns detailed token information including:
  - `active`: Whether token is valid/active
  - `sub`: Subject (userId)
  - `aud`: Audience (intended for which client)
  - `username`: Username
  - `exp`: Expiration timestamp
  - `iat`: Issued at timestamp
  - Other OIDC claims

**Error Handling:**
- **Token Inactive/Invalid**: Returns `TOKEN_INVALID` error
- **Keycloak Server Error**: Returns `KEYCLOAK_SERVER_ERROR`
- **Connection Error**: Returns `KEYCLOAK_CONNECTION_ERROR`

**Use Cases:**
- Validating tokens received from clients
- Getting user info from token
- Security checks before processing requests

**Example:**
```java
TokenIntrospectionResponse tokenInfo = keycloakService.introspectToken(accessToken);
if (tokenInfo.getActive()) {
    String username = tokenInfo.getUsername();
    String userId = tokenInfo.getSubject();
}
```

---

#### `decodeToken(String userId): KCResponse<TokenInfoDTO>`
Decodes JWT token and extracts claims information.

**Business Logic:**
- Performs JWT decoding without signature validation
- Extracts claims: userId, username, email, roles, etc.
- **Warning**: Does NOT validate token authenticity
- Use for extracting information only, not for security validation

**Differences from `introspectToken()`:**
- `decodeToken()`: Local JWT decoding, no server call, NO signature validation
- `introspectToken()`: Server-side validation, secure, validates signature and expiration

**Returns:**
- `TokenInfoDTO` containing decoded claims

**Warning:**
- Do NOT use for security-critical operations
- Prefer `introspectToken()` when security is important
- Only use for reading token information for logging/debugging

---

### 5. **Utility Methods**

#### `isUserExsist(String userId): Boolean`
Checks if a user exists in Keycloak by userId.

**Business Logic:**
- Attempts to fetch user profile via admin API
- Returns true if user found, false otherwise
- Requires admin access token

**Error Handling:**
- Returns boolean, no exception thrown

**Example:**
```java
if (keycloakService.isUserExsist(userId)) {
    // User exists
}
```

---

## Error Handling

The service uses custom exception codes defined in `AuthzErrorCode`:

- **INVALID_USER_NAME_OR_PASSWORD**: Wrong password or invalid credentials
- **USER_NOT_FOUND**: User doesn't exist
- **NOT_FOUND_REALM_ROLE**: Realm role doesn't exist
- **CLIENT_ROLE_NOT_FOUND**: Client role doesn't exist
- **ROLE_NOT_FOUND**: Generic role not found
- **TOKEN_INVALID**: Token is invalid, expired, or revoked
- **VALIDATION_ERROR**: Input validation failed
- **DUPLICATE**: Duplicate username, email, or other unique field
- **FORBIDDEN**: Permission denied
- **UNAUTHORIZED**: Authentication failed
- **CLIENT_NOT_FOUND**: Client doesn't exist
- **API_ERROR**: Unexpected API error
- **UNKNOWN_ERROR**: Unknown error
- **KEYCLOAK_SERVER_ERROR**: Server-side error from Keycloak
- **KEYCLOAK_CONNECTION_ERROR**: Cannot connect to Keycloak server

## Authentication Flow

### User Login Flow:
```
1. login(username, password)
   ↓
2. Send OAuth2 password grant request to Keycloak
   ↓
3. Receive: access_token, refresh_token, expires_in
   ↓
4. Client stores refresh_token securely
   ↓
5. Client uses access_token for API requests (Bearer token)
```

### Token Refresh Flow:
```
1. Access token expires
   ↓
2. refreshToken(refresh_token)
   ↓
3. Receive new access_token and refresh_token
   ↓
4. Client updates token and continues
```

### Logout Flow:
```
1. logout(refresh_token)
   ↓
2. Keycloak revokes refresh_token
   ↓
3. User cannot refresh token anymore
   ↓
4. Access token remains valid until expiration (can be introspected)
```

## Configuration

The service is configured via `KeyCloakProperties`:
- `domainUrl`: Keycloak server URL (e.g., http://localhost:8080/auth)
- `realmName`: Keycloak realm name
- `clientId`: Client application ID
- `clientSecret`: Client secret for OAuth2 flows
- `adminUsername`: Admin user for Keycloak admin API
- `adminPassword`: Admin password

## Best Practices

1. **Token Management:**
   - Store refresh tokens securely (HTTP-only cookies preferred)
   - Use access tokens for API authorization (Bearer header)
   - Refresh tokens before expiration using background job

2. **Role-Based Access Control:**
   - Check user roles before sensitive operations
   - Use `userHasRealmRole()` or `userHasClientRole()` for permission checks
   - Cache role information to reduce API calls (with reasonable TTL)

3. **Error Handling:**
   - Always check `KCResponse.isSuccess()` before accessing data
   - Log error codes for debugging
   - Handle specific error codes appropriately in UI/client

4. **Security:**
   - Never log passwords or sensitive tokens
   - Use HTTPS for all Keycloak communication
   - Validate token expiration client-side before use
   - Perform server-side token validation via `introspectToken()`

5. **Performance:**
   - Batch role assignments when possible
   - Cache user data with appropriate TTL
   - Use async operations for non-critical updates

## Example Usage

```java
@Service
public class AuthService {
    
    @Autowired
    private KeyCloakService keycloakService;
    
    // User registration with role assignment
    public UserInformation registerNewUser(String username, String email, 
                                          String password, String role) {
        RegisterRequest req = new RegisterRequest();
        req.setUserName(username);
        req.setEmail(email);
        req.setPassword(password);
        req.setFirstName("First");
        req.setLastName("Last");
        
        KCResponse<UserInformation> response = 
            keycloakService.register(req, role);
            
        if (response.isSuccess()) {
            return response.getData();
        } else {
            throw new AuthenticationException(response.getError().getMessage());
        }
    }
    
    // Check user authorization
    public boolean canUserAccess(String userId, String requiredRole) {
        return keycloakService.userHasRealmRole(userId, requiredRole);
    }
    
    // Refresh user token
    public TokenResponse refreshUserToken(String refreshToken) {
        KCResponse<TokenResponse> response = 
            keycloakService.refreshToken(refreshToken);
            
        if (response.isSuccess()) {
            return response.getData();
        }
        throw new TokenException("Token refresh failed");
    }
}
```

---

## Summary

The `KeyCloakService` provides a comprehensive, well-documented interface for all Keycloak operations needed in a modern Spring Boot application. It abstracts away Keycloak's REST API complexity while providing clear error handling and type-safe responses.

