package org.ldang.keycloack.service;

import org.ldang.keycloack.dto.role.RealmRoleResponse;
import org.ldang.keycloack.dto.role.RoleResponse;
import org.ldang.keycloack.dto.token.TokenInfoDTO;
import org.ldang.keycloack.dto.token.TokenIntrospectionResponse;
import org.ldang.keycloack.dto.token.TokenResponse;
import org.ldang.keycloack.dto.user.RegisterRequest;
import org.ldang.keycloack.dto.user.UpdateUserRequest;
import org.ldang.keycloack.dto.user.UserInformation;
import org.ldang.keycloack.utils.KCResponse;

import java.util.List;
import java.util.Map;

/**
 * Service interface for interacting with Keycloak.
 *
 * <p>This interface provides methods to manage users, roles, and tokens in Keycloak.
 * Each method lists expected behavior, success cases, and exception handling.</p>
 */
public interface KeyCloakService {

    /**
     * Login user to Keycloak and get access token.
     *
     * <p>Behavior:</p>
     * <ul>
     *   <li>If login succeeds, return {@link TokenResponse} containing access and refresh token.</li>
     *   <li>If password is wrong, throw {@link AuthzException} with message "Invalid username or password".</li>
     *   <li>If username not found, throw {@link UserNotFoundException}.</li>
     * </ul>
     *
     * @param userName The username of the user.
     * @param password The password of the user.
     * @return {@link TokenResponse} containing access token, refresh token, and expiration info.
     * @throws UserNotFoundException if the username does not exist.
     * @throws AuthzException if password is invalid or Keycloak returns error.
     */
     KCResponse<TokenResponse> login(String userName, String password);

    /**
     * Register a new user in Keycloak without assigning a role.
     *
     * <p>Behavior:</p>
     * <ul>
     *   <li>If registration succeeds, return the {@link String} userId of the new user.</li>
     *   <li>If username or email already exists, throw {@link AuthzException} with code USERNAME_EXISTS.</li>
     *   <li>If any required field is missing or invalid, throw {@link AuthzException} with code BAD_REQUEST.</li>
     * </ul>
     *
     * @param userName The username of the new user.
     * @param password The password for the new user.
     * @param email The email of the new user.
     * @param firstName The first name of the new user.
     * @param lastName The last name of the new user.
     * @return The userId of the created user.
     * @throws AuthzException if username/email already exists or input is invalid.
     */
    KCResponse<UserInformation> register(RegisterRequest req);

    /**
     * Register a new user in Keycloak and assign a role.
     *
     * <p>Behavior:</p>
     * <ul>
     *   <li>If registration succeeds, return the {@link String} userId of the new user.</li>
     *   <li>If a role is specified, assign it to the user after creation.</li>
     *   <li>If username or email already exists, throw {@link AuthzException} with code USERNAME_EXISTS.</li>
     *   <li>If any required field is missing or invalid, throw {@link AuthzException} with code BAD_REQUEST.</li>
     * </ul>
     *
     * @param userName The username of the new user.
     * @param password The password for the new user.
     * @param email The email of the new user.
     * @param firstName The first name of the new user.
     * @param lastName The last name of the new user.
     * @param role The role to assign to the user (optional).
     * @return The userId of the created user.
     * @throws AuthzException if username/email already exists or input is invalid.
     */
    KCResponse<UserInformation> register(RegisterRequest req, String role);

    /**
     * Get user information by username.
     *
     * <p>Behavior:</p>
     * <ul>
     *   <li>If user exists, return {@link UserInformation} with details including id, email, firstName, lastName, and roles.</li>
     *   <li>If user does not exist, throw {@link UserNotFoundException}.</li>
     * </ul>
     *
     * @param userName The username of the user.
     * @return {@link UserInformation} containing full information of the user.
     * @throws UserNotFoundException if the user does not exist.
     */
    KCResponse<UserInformation> getUserByUsername(String userName);

    /**
     * Assign a realm role to a user.
     *
     * <p>This method assigns a realm-level role to a specific user. Realm roles are global roles
     * that apply across the entire Keycloak realm, not limited to specific clients.</p>
     *
     * <p>Behavior:</p>
     * <ul>
     *   <li>Retrieves the realm role data by role name.</li>
     *   <li>If role exists, maps the role to the user via the Keycloak admin API.</li>
     *   <li>Returns the updated {@link UserInformation} with all roles after assignment.</li>
     *   <li>If role does not exist, throws {@link AuthzException} with code NOT_FOUND_REALM_ROLE.</li>
     *   <li>If user does not exist, throws {@link AuthzException} with code USER_NOT_FOUND.</li>
     * </ul>
     *
     * @param userId The unique identifier (UUID) of the user.
     * @param roleName The name of the realm role to assign (case-sensitive).
     * @return {@link KCResponse} containing updated {@link UserInformation} with all assigned roles.
     * @throws AuthzException if the role does not exist or with code NOT_FOUND_REALM_ROLE.
     * @throws AuthzException if the user does not exist or with code USER_NOT_FOUND.
     */
    KCResponse<UserInformation> assignRealmRole(String userId, String roleName);

    /**
     * Assign a client role to a user.
     *
     * <p>This method assigns a client-specific role to a user. Client roles are scoped to a particular
     * client application and are not visible to other clients in the realm.</p>
     *
     * <p>Implementation Details:</p>
     * <ul>
     *   <li>Retrieves the client UUID from the configured client ID.</li>
     *   <li>Fetches the specific client role by role name.</li>
     *   <li>Maps the client role to the user using the Keycloak admin API.</li>
     *   <li>Returns the updated user information with both realm and client roles populated.</li>
     * </ul>
     *
     * <p>Behavior:</p>
     * <ul>
     *   <li>If role assignment succeeds, the user has the role in the specified client.</li>
     *   <li>If the client role does not exist, throws {@link AuthzException} with code CLIENT_ROLE_NOT_FOUND.</li>
     *   <li>If the user does not exist, throws {@link AuthzException} with code USER_NOT_FOUND.</li>
     * </ul>
     *
     * @param userId The unique identifier (UUID) of the user.
     * @param roleName The name of the client role to assign (case-sensitive).
     * @return {@link KCResponse} containing updated {@link UserInformation} with all assigned roles.
     * @throws AuthzException with code CLIENT_ROLE_NOT_FOUND if the role does not exist.
     * @throws AuthzException with code USER_NOT_FOUND if the user does not exist.
     */

    KCResponse<UserInformation> assignClientRole(String userId, String roleName);

    /**
     * Get all roles of a user by username.
     *
     * <p>Behavior:</p>
     * <ul>
     *   <li>If user exists, return {@link RoleResponse} containing both realm and client roles.</li>
     *   <li>If user does not exist, throw {@link UserNotFoundException}.</li>
     * </ul>
     *
     * @param username The username of the user.
     * @return {@link RoleResponse} containing all roles of the user.
     * @throws UserNotFoundException if the user does not exist.
     */
    KCResponse<RoleResponse> getAllRolesOfUser(String username);

    /**
     * Get realm roles of a user by userId.
     *
     * <p>This method retrieves all realm-level roles assigned to a user. Realm roles are global
     * roles that apply across the entire Keycloak realm.</p>
     *
     * <p>Implementation Details:</p>
     * <ul>
     *   <li>Queries the Keycloak admin API for all roles mapped to the user at the realm level.</li>
     *   <li>Extracts the "name" field from each role representation.</li>
     *   <li>Returns an empty list if the user has no realm roles.</li>
     * </ul>
     *
     * @param userId The unique identifier (UUID) of the user.
     * @return {@link List} of realm role names (String) assigned to the user. Returns empty list if no roles.
     */
    List<String> getRealmRolesOfUser(String userId);

    /**
     * Get client roles of a user by userId.
     *
     * <p>This method retrieves all client-specific roles assigned to a user. Client roles are scoped
     * to specific client applications and are organized by client ID.</p>
     *
     * <p>Implementation Details:</p>
     * <ul>
     *   <li>Iterates through all clients in the realm.</li>
     *   <li>For each client, queries all roles mapped to the user.</li>
     *   <li>Organizes results as a map with client names (clientId) as keys.</li>
     *   <li>Only includes clients in the map if the user has at least one role in that client.</li>
     * </ul>
     *
     * @param userId The unique identifier (UUID) of the user.
     * @return {@link Map} with client names as keys and {@link List} of client role names as values.
     *         Empty map if user has no client roles or belongs to no clients.
     */
    Map<String, List<String>> getClientRolesOfUser(String userId);

    /**
     * Refresh access token using refresh token.
     *
     * <p>Behavior:</p>
     * <ul>
     *   <li>If refresh token is valid, return new {@link TokenResponse}.</li>
     *   <li>If refresh token expired or invalid, throw {@link AuthzException} with code TOKEN_INVALID.</li>
     * </ul>
     *
     * @param refreshToken The refresh token to use.
     * @return {@link TokenResponse} containing new access and refresh tokens.
     * @throws AuthzException if refresh token is invalid or expired.
     */
    KCResponse<TokenResponse> refreshToken(String refreshToken);

    /**
     * Logout a user by revoking the refresh token.
     *
     * @param refreshToken The refresh token to revoke.
     */
    KCResponse<?> logout(String refreshToken);

    /**
     * Get user information by userId.
     *
     * @param userId The id of the user.
     * @return {@link UserInformation} containing full information of the user.
     * @throws UserNotFoundException if user does not exist.
     */
    KCResponse<UserInformation> getUserById(String userId);

    /**
     * Introspect a token to check its validity and retrieve user info.
     *
     * <p>Behavior:</p>
     * <ul>
     *   <li>If token is active, return {@link TokenIntrospectionResponse} with user info and roles.</li>
     *   <li>If token is inactive or invalid, throw {@link AuthzException} with code TOKEN_INVALID.</li>
     * </ul>
     *
     * @param token The access token to introspect.
     * @return {@link TokenIntrospectionResponse} with token status and user info.
     * @throws AuthzException if token is invalid or inactive.
     */
    TokenIntrospectionResponse introspectToken(String token);

    /**
     * Update user information by userId.
     *
     * @param userId The id of the user.
     * @param req {@link UpdateUserRequest} containing fields to update.
     * @throws UserNotFoundException if user does not exist.
     * @throws AuthzException if update data is invalid.
     */
    KCResponse<UserInformation> updateUserByUserId(String userId, UpdateUserRequest req);

    /**
     * Update user information by username.
     *
     * @param userName The username of the user.
     * @param req {@link UpdateUserRequest} containing fields to update.
     * @throws UserNotFoundException if user does not exist.
     * @throws AuthzException if update data is invalid.
     */
    KCResponse<UserInformation> updateUserByUserName(String userName, UpdateUserRequest req);

    /**
     * Enable a user by userId.
     *
     * @param userId The id of the user.
     * @throws UserNotFoundException if user does not exist.
     */
    KCResponse<UserInformation> enableUserByUserId(String userId);

    /**
     * Disable a user by userId.
     *
     * @param userId The id of the user.
     * @throws UserNotFoundException if user does not exist.
     */
    KCResponse<UserInformation> disableUserByUserId(String userId);

    /**
     * Enable a user by username.
     *
     * @param userName The username of the user.
     * @throws UserNotFoundException if user does not exist.
     */
    KCResponse<UserInformation> enableUserByUserName(String userName);

    /**
     * Disable a user by username.
     *
     * @param userName The username of the user.
     * @throws UserNotFoundException if user does not exist.
     */
    KCResponse<UserInformation> disableUserByUserName(String userName);

    /**
     * Reset password for a user by admin.
     *
     * @param userId The id of the user.
     * @param newPassword The new password.
     * @param temporary Whether the password is temporary.
     * @throws UserNotFoundException if user does not exist.
     * @throws AuthzException if password violates policy.
     */
    KCResponse<?> resetPassword(String userId, String newPassword, boolean temporary);

    /**
     * Change password by user.
     *
     * @param username The username of the user.
     * @param oldPassword The current password.
     * @param newPassword The new password.
     * @throws UserNotFoundException if user does not exist.
     * @throws AuthzException if old password is invalid or new password violates policy.
     */
    KCResponse<?> changePassword(String username, String oldPassword, String newPassword);

    /**
     * Remove a realm role from a user.
     *
     * <p>This method revokes a previously assigned realm-level role from a user. After removal,
     * the user will no longer have access to resources protected by this role.</p>
     *
     * <p>Implementation Details:</p>
     * <ul>
     *   <li>Retrieves the role definition from Keycloak using the role name.</li>
     *   <li>Sends a DELETE request to unmap the role from the user.</li>
     *   <li>Returns the updated user information with the role removed from their realm roles list.</li>
     * </ul>
     *
     * <p>Behavior:</p>
     * <ul>
     *   <li>If removal succeeds, the user no longer has the specified realm role.</li>
     *   <li>If the realm role does not exist, throws {@link AuthzException} with code NOT_FOUND_REALM_ROLE.</li>
     *   <li>If the user does not exist, throws {@link AuthzException} with code USER_NOT_FOUND.</li>
     * </ul>
     *
     * @param userId The unique identifier (UUID) of the user.
     * @param roleName The name of the realm role to remove (case-sensitive).
     * @return {@link KCResponse} containing updated {@link UserInformation} with the role removed.
     * @throws AuthzException with code NOT_FOUND_REALM_ROLE if the role does not exist.
     * @throws AuthzException with code USER_NOT_FOUND if the user does not exist.
     */
    KCResponse<UserInformation>  removeRealmRoleFromUser(String userId, String roleName);

    /**
     * Remove a client role from a user.
     *
     * <p>This method revokes a previously assigned client-specific role from a user. Client roles
     * are scoped to a particular client application.</p>
     *
     * <p>Implementation Details:</p>
     * <ul>
     *   <li>Retrieves the client UUID from the configured client ID.</li>
     *   <li>Fetches the specific client role definition by role name.</li>
     *   <li>Sends a DELETE request to unmap the client role from the user.</li>
     *   <li>Returns the updated user information with the role removed from client roles.</li>
     * </ul>
     *
     * <p>Behavior:</p>
     * <ul>
     *   <li>If removal succeeds, the user no longer has the specified client role.</li>
     *   <li>If the client role does not exist, throws {@link AuthzException} with code ROLE_NOT_FOUND.</li>
     *   <li>If the user does not exist, throws {@link AuthzException} with code USER_NOT_FOUND.</li>
     * </ul>
     *
     * @param userId The unique identifier (UUID) of the user.
     * @param clientId The id of the client (note: this parameter is not actively used in the implementation,
     *                 the client is determined from the configured client ID).
     * @param roleName The name of the client role to remove (case-sensitive).
     * @return {@link KCResponse} containing updated {@link UserInformation} with the role removed.
     * @throws AuthzException with code ROLE_NOT_FOUND if the role does not exist.
     * @throws AuthzException with code USER_NOT_FOUND if the user does not exist.
     */
    KCResponse<UserInformation>  removeClientRoleFromUser(String userId, String roleName);

    /**
     * Check if a user has a specific realm role.
     *
     * <p>This method performs a boolean check to determine whether a user possesses a given realm role.
     * Realm roles are global roles in the Keycloak realm.</p>
     *
     * <p>Implementation Details:</p>
     * <ul>
     *   <li>Retrieves all realm roles assigned to the user.</li>
     *   <li>Uses a stream-based search to match the specified role name.</li>
     *   <li>Returns false if an API error occurs or if the user is not found (no exception thrown).</li>
     * </ul>
     *
     * @param userId The unique identifier (UUID) of the user.
     * @param roleName The name of the realm role to check for (case-sensitive).
     * @return true if the user has the specified realm role, false otherwise.
     */
    boolean userHasRealmRole(String userId, String roleName);

    /**
     * Check if a user has a specific client role.
     *
     * <p>This method performs a boolean check to determine whether a user possesses a given client-specific role.
     * Client roles are scoped to a particular client application.</p>
     *
     * <p>Implementation Details:</p>
     * <ul>
     *   <li>Retrieves the configured client UUID.</li>
     *   <li>Queries all client roles mapped to the user for that client.</li>
     *   <li>Uses a stream-based search to match the specified role name.</li>
     *   <li>Returns false if an API error occurs or if the user/client is not found (no exception thrown).</li>
     * </ul>
     *
     * @param userId The unique identifier (UUID) of the user.
     * @param clientId The id of the client (note: this parameter is not actively used in the implementation,
     *                 the client is determined from the configured client ID).
     * @param roleName The name of the client role to check for (case-sensitive).
     * @return true if the user has the specified client role, false otherwise.
     */
    boolean userHasClientRole(String userId, String roleName);

    /**
     * Get realm role data by role name.
     *
     * <p>This method retrieves detailed information about a specific realm role from Keycloak.
     * It requires admin privileges to access the role metadata.</p>
     *
     * <p>Implementation Details:</p>
     * <ul>
     *   <li>Queries the Keycloak admin API for role details by name.</li>
     *   <li>Returns a {@link RealmRoleResponse} containing full role information.</li>
     *   <li>Handles multiple error scenarios: 404 (Not Found), 403 (Forbidden), 401 (Unauthorized).</li>
     * </ul>
     *
     * <p>Behavior:</p>
     * <ul>
     *   <li>If role exists, returns {@link KCResponse} with role data.</li>
     *   <li>If role not found, throws {@link AuthzException} with code NOT_FOUND_REALM_ROLE.</li>
     *   <li>If insufficient permissions, throws {@link AuthzException} with code FORBIDDEN.</li>
     *   <li>If token is invalid or expired, throws {@link AuthzException} with code UNAUTHORIZED.</li>
     * </ul>
     *
     * @param roleName The name of the realm role to retrieve data for (case-sensitive).
     * @return {@link KCResponse} containing {@link RealmRoleResponse} with role metadata.
     * @throws AuthzException with code NOT_FOUND_REALM_ROLE if role does not exist.
     * @throws AuthzException with code FORBIDDEN if insufficient permissions.
     * @throws AuthzException with code UNAUTHORIZED if token is invalid or expired.
     * @throws AuthzException with code API_ERROR for other unexpected errors.
     */
    KCResponse<RealmRoleResponse> getRealmRoleData(String roleName);

    /**
     * Check if a user exists in Keycloak by userId.
     *
     * <p>This method verifies the existence of a user in the Keycloak realm by attempting to retrieve
     * the user's profile from the Keycloak admin API.</p>
     *
     * <p>Implementation Details:</p>
     * <ul>
     *   <li>Performs a GET request to fetch user data by userId.</li>
     *   <li>Requires admin access token for authorization.</li>
     *   <li>Returns boolean result indicating user existence.</li>
     * </ul>
     *
     * @param userId The unique identifier (UUID) of the user to check.
     * @return true if the user exists in Keycloak, false otherwise.
     */
    Boolean isUserExist(String userId);

    /**
     * Decode and extract information from an access token.
     *
     * <p>This method decodes a JWT access token and extracts claims information without validating
     * the token signature. It is useful for extracting user information from the token payload.</p>
     *
     * <p>Implementation Details:</p>
     * <ul>
     *   <li>Uses JWT decoding to parse the access token.</li>
     *   <li>Extracts standard claims like userId, username, email, etc.</li>
     *   <li>Does not perform signature verification or expiration check.</li>
     * </ul>
     *
     * <p>Note: This method should be used cautiously as it does not validate token authenticity.
     * For security-critical operations, use {@link #introspectToken(String)} instead.</p>
     *
     * @param userId The userId extracted from the token (used as parameter name, but typically the access token is used internally).
     * @return {@link KCResponse} containing {@link TokenInfoDTO} with decoded token information (userId, username, email, roles, etc.).
     */
    KCResponse<TokenInfoDTO> decodeToken(String userId);
}
