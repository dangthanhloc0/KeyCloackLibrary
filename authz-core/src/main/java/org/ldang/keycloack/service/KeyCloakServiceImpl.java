package org.ldang.keycloack.service;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.ldang.keycloack.Configuration.KeyCloakProperties;

import java.util.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.ldang.keycloack.constans.AuthzConstans;
import org.ldang.keycloack.constans.AuthzErrorCode;
import org.ldang.keycloack.dto.role.RealmRoleResponse;
import org.ldang.keycloack.dto.role.RoleRepresentation;
import org.ldang.keycloack.dto.role.RoleResponse;
import org.ldang.keycloack.dto.token.TokenInfoDTO;
import org.ldang.keycloack.dto.token.TokenIntrospectionResponse;
import org.ldang.keycloack.dto.token.TokenResponse;
import org.ldang.keycloack.dto.user.RegisterRequest;
import org.ldang.keycloack.dto.user.UpdateUserRequest;
import org.ldang.keycloack.dto.user.UserInformation;
import org.ldang.keycloack.utils.KCResponse;
import org.ldang.keycloack.utils.TokenDecoder;
import org.ldang.keycloack.utils.validation.ValidatorUtil;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import static org.ldang.keycloack.constans.AuthzErrorCode.USER_NOT_FOUND;
import static org.ldang.keycloack.exception.GlobalExceptionCustom.handleKeyCloakException;
import static org.ldang.keycloack.exception.GlobalExceptionCustom.handleKeycloakValidation;
import static org.ldang.keycloack.helper.CommonHelpers.createAdminHeaders;
import static org.ldang.keycloack.helper.CommonHelpers.createHeaders;


public class KeyCloakServiceImpl implements KeyCloakService {


    private final RestTemplate restTemplate;
    private final KeyCloakProperties props;
    private final ObjectMapper objectMapper;
    private String mainURL = "";
    private String adminRealmsUrl = "";
    private final TokenDecoder tokenDecoder;


    public KeyCloakServiceImpl(KeyCloakProperties props, RestTemplate restTemplate, TokenDecoder tokenDecoder,ObjectMapper objectMapper) {
        this.props = props;
        this.restTemplate = restTemplate;
        this.mainURL = props.getDomainUrl() + AuthzConstans.ADMIN_REALM + props.getRealmName();
        this.adminRealmsUrl = props.getDomainUrl() + AuthzConstans.REALMS_MASTER + "protocol/openid-connect";
        this.tokenDecoder = tokenDecoder;
        this.objectMapper = objectMapper;
    }

    public String getAccessToken() {
        try {
            MultiValueMap<Object, Object> data = new LinkedMultiValueMap<>();
            data.add("grant_type", "password");
            data.add("client_id", "admin-cli");
            data.add("username", props.getAdminUsername());
            data.add("password", props.getAdminPassword());

            HttpHeaders headers = createHeaders();

            String url = adminRealmsUrl+ AuthzConstans.TOKEN;
            var res = restTemplate.postForEntity(
                    url,
                    new HttpEntity<>(data, headers),
                    JsonNode.class
            );
            return res.getBody().get("access_token").asText();
        } catch (HttpClientErrorException e) {
            String errorMsg = "";
            try {
                Map<String, Object> errorBody = new ObjectMapper().readValue(e.getResponseBodyAsString(), Map.class);
                errorMsg =  (String) errorBody.get("error_description");
                if(errorMsg == null) {
                    errorMsg = errorBody.get("errorMessage").toString();
                }
            } catch (Exception ex) {
                errorMsg = e.getMessage();
            }
            handleKeyCloakException(AuthzErrorCode.INVALID_ADMIN_CREDENTIALS, errorMsg);
        }
        return  null;
    }



    @Override
    public KCResponse<TokenResponse> login(String userName , String password) {
        try {
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "password");
            body.add("client_id", props.getClientId());
            body.add("client_secret", props.getClientSecret());
            body.add("username", userName);
            body.add("password", password);

            String URlLogin = props.getDomainUrl() + AuthzConstans.REALM + props.getRealmName() + AuthzConstans.PROTOCOL_OPENID_CONNECT + AuthzConstans.TOKEN;
            HttpHeaders headers = createHeaders();
            ResponseEntity<TokenResponse> res = restTemplate.exchange(
                    URlLogin,
                    HttpMethod.POST,
                    new HttpEntity<>(body, headers),
                    TokenResponse.class
            );
            return KCResponse.success(res.getBody());
        } catch (HttpClientErrorException.Unauthorized e) {
            return handleKeyCloakException(AuthzErrorCode.INVALID_USER_NAME_OR_PASSWORD, null);
        } catch (HttpClientErrorException e) {
            String errorMsg = "";
            try {
                Map<String, Object> errorBody = new ObjectMapper().readValue(e.getResponseBodyAsString(), Map.class);
                errorMsg = (String) errorBody.get("error_description");
                if (errorMsg == null) {
                    errorMsg = errorBody.get("errorMessage").toString();
                }
            } catch (Exception ex) {
                errorMsg = e.getMessage();
            }
            return handleKeyCloakException(AuthzErrorCode.VALIDATION_ERROR, errorMsg);
        }

    }

    @Override
    public KCResponse<UserInformation> register(RegisterRequest req) {

        var errors = ValidatorUtil.validateFields(req);
        if (!errors.isEmpty()) {
            return handleKeycloakValidation(AuthzErrorCode.VALIDATION_ERROR, errors);
        }

        try{
            String adminToken = getAccessToken();
            Object [] credentials = {
                    Map.of(
                            "type" , "password",
                            "value" , req.getPassword(),
                            "temporary" , false
                    )
            };
            Map<Object , Object> body = new HashMap<>();
            body.put("username" , req.getUserName());
            body.put("email" , req.getEmail());
            body.put("firstName" , req.getFirstName());
            body.put("lastName" , req.getLastName());
            body.put("enabled" , true);
            body.put("emailVerified", true);
            body.put("credentials" , credentials);

            String url = props.getDomainUrl() + AuthzConstans.ADMIN_REALM + props.getRealmName() + "/users";
            ResponseEntity<Void> res = restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    new HttpEntity<>(body, createAdminHeaders(adminToken)),
                    Void.class
            );

            String location = res.getHeaders().getFirst("Location");
            String userId = "null";
            if (location != null && !location.isEmpty()) {
                userId = location.substring(location.lastIndexOf('/') + 1);
            } else {
                return handleKeyCloakException(USER_NOT_FOUND, userId);
            }
            var user = getUserById(userId);
            if(user.isSuccess()) {
                return KCResponse.success(user.getData());
            }

        } catch (HttpClientErrorException e) {
            String errorMsg = "";
            try {
                Map<String, Object> errorBody = new ObjectMapper().readValue(e.getResponseBodyAsString(), Map.class);
                errorMsg =  (String) errorBody.get("error_description");
                if(errorMsg == null) {
                    errorMsg = errorBody.get("errorMessage").toString();
                }
            } catch (Exception ex) {
                errorMsg = e.getMessage();
            }
            return  handleKeyCloakException(AuthzErrorCode.VALIDATION_ERROR, errorMsg);
        }
        return  null;
    }


    @Override
    public KCResponse<UserInformation> register(RegisterRequest req, String role) {
        var errors = ValidatorUtil.validateFields(req);
        if (!errors.isEmpty()) {
            return handleKeycloakValidation(AuthzErrorCode.VALIDATION_ERROR, errors);
        }

        try{
            String adminToken = getAccessToken();
            Object [] credentials = {
                    Map.of(
                            "type" , "password",
                            "value" ,req.getPassword(),
                            "temporary" , false
                    )
            };
            Map<Object , Object> body = new HashMap<>();
            body.put("username" , req.getUserName());
            body.put("email" , req.getEmail());
            body.put("firstName" , req.getFirstName());
            body.put("lastName" , req.getLastName());
            body.put("enabled" , true);
            body.put("emailVerified", true);
            body.put("credentials" , credentials);

            String url = props.getDomainUrl() + AuthzConstans.ADMIN_REALM + props.getRealmName() + "/users";
            ResponseEntity<Void> res = restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    new HttpEntity<>(body, createAdminHeaders(adminToken)),
                    Void.class
            );

            String location = res.getHeaders().getFirst("Location");
            String userId = "null";
            if (location != null && !location.isEmpty()) {
                userId = location.substring(location.lastIndexOf('/') + 1);
            } else {
                return handleKeyCloakException(USER_NOT_FOUND, userId);
            }
            assignRealmRole(req.getEmail(), role);
            var user = getUserById(userId);
            if(user.isSuccess()) {
                return KCResponse.success(user.getData());
            }

        } catch (HttpClientErrorException e) {
            String errorMsg = "";
            try {
                Map<String, Object> errorBody = new ObjectMapper().readValue(e.getResponseBodyAsString(), Map.class);
                errorMsg = (String) errorBody.getOrDefault("errorMessage", e.getMessage());
            } catch (Exception ex) {
                errorMsg = e.getMessage();
            }
            return  handleKeyCloakException(AuthzErrorCode.VALIDATION_ERROR, errorMsg);
        }
        return null;
    }

    @Override
    public KCResponse<UserInformation> getUserByUsername(String userName) {
        try {
            String url = props.getDomainUrl() + AuthzConstans.ADMIN_REALM + props.getRealmName() + AuthzConstans.ENQUIRE_USER + userName+"&exact=true";
            String token = getAccessToken();

            HttpHeaders headers = createAdminHeaders(token);
            ResponseEntity<List<UserInformation>> response =
                    restTemplate.exchange(
                            url,
                            HttpMethod.GET,
                            new HttpEntity<>(headers),
                            new ParameterizedTypeReference<>() {
                            }
                    );

            List<UserInformation> users = response.getBody();
            UserInformation user = users != null && !users.isEmpty()
                    ? users.get(0)
                    : null;

            if(user == null) {
                return handleKeyCloakException(AuthzErrorCode.USER_NOT_FOUND, userName);
            }

            String userId = user.getId();

            var realmRolesList = getRealmRolesOfUser(userId);

            user.setRealmRoles(realmRolesList);

            var clientRolesMap = getClientRolesOfUser(userId);
            user.setClientRoles(clientRolesMap);


            return  KCResponse.success(user);
        } catch (HttpClientErrorException e) {
            handleKeyCloakException(AuthzErrorCode.API_ERROR, e.getMessage());
        }
        return null;
    }

    @Override
    public KCResponse<UserInformation> assignRealmRole(String userId, String roleName) {
        try {
            String token = getAccessToken();

            var realmRoleData = getRealmRoleData(roleName);
            if(!realmRoleData.isSuccess()) {
                return handleKeyCloakException(AuthzErrorCode.NOT_FOUND_REALM_ROLE, roleName);
            }
            ArrayNode body = objectMapper.createArrayNode();
            body.add(objectMapper.valueToTree(realmRoleData.getData()));

            HttpHeaders headers = createAdminHeaders(token);
            String url = mainURL + AuthzConstans.USER + userId + AuthzConstans.MAPPING_ROLE;
            restTemplate.postForEntity(
                    url,
                    new HttpEntity<>(body, headers),
                    Void.class
            );
            return getUserById(userId);
        } catch (HttpClientErrorException e) {
            if(e.getStatusCode().is4xxClientError()){
                return handleKeyCloakException(USER_NOT_FOUND, userId);
            }
            throw new RuntimeException(e);
        }

    }


    @Override
    public KCResponse<UserInformation> assignClientRole(String userId, String roleName) {
        try {
            String token = getAccessToken();
            JsonNode clients = getClient(token);
            String clientUuid = clients.get(0).get("id").asText();

            var res = getClientRole(clientUuid, roleName, token);
            if(!res.isSuccess()) {
                return handleKeyCloakException(AuthzErrorCode.CLIENT_ROLE_NOT_FOUND, roleName);
            }
            ArrayNode body = objectMapper.createArrayNode();
            body.add((JsonNode) res.getData());

            HttpHeaders headers = createAdminHeaders(token);

            HttpEntity<JsonNode> assignEntity = new HttpEntity<>(body, headers);
            String assignUrl = mainURL + AuthzConstans.USER
                    + userId + AuthzConstans.MAPPING_CLIENT_ROLE  + clientUuid;

            restTemplate.postForEntity(assignUrl, assignEntity, Void.class);
            return getUserById(userId);
        } catch (HttpClientErrorException e) {
            if(e.getStatusCode().is4xxClientError()){
                return handleKeyCloakException(USER_NOT_FOUND, userId);
            }
            throw new RuntimeException(e);
        }
    }

    private JsonNode getClient(String token) {
        String clientUrl = mainURL + AuthzConstans.ENQUIRE_CLIENT + props.getClientId();

        HttpHeaders headers = createAdminHeaders(token);
        HttpEntity<Void> entity = new HttpEntity<>(headers);

        ResponseEntity<JsonNode> clientRes = restTemplate.exchange(
                clientUrl,
                HttpMethod.GET,
                entity,
                JsonNode.class
        );

        JsonNode clients = clientRes.getBody();
        if (clients == null || !clients.isArray() || clients.isEmpty()) {
            handleKeyCloakException(AuthzErrorCode.CLIENT_NOT_FOUND, null);
        }
        return  clients;
    }


    private KCResponse<?> getClientRole(String clientUuid, String roleName, String token) {
        try{
            String roleUrl = mainURL + AuthzConstans.CLIENT + clientUuid + AuthzConstans.ROLES + roleName;
            HttpHeaders headers = createAdminHeaders(token);
            ResponseEntity<JsonNode> roleResponse = restTemplate.exchange(
                    roleUrl,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    JsonNode.class
            );

            return KCResponse.success(roleResponse.getBody());
        } catch (HttpClientErrorException e) {
            return handleKeyCloakException(AuthzErrorCode.CLIENT_ROLE_NOT_FOUND, roleName);
        }
    }

    @Override
    public KCResponse<RealmRoleResponse> getRealmRoleData(String roleName) {
        String url = mainURL + AuthzConstans.ROLES + roleName;
        String token = getAccessToken();
        HttpHeaders headers = createAdminHeaders(token);

        try {
            ResponseEntity<RealmRoleResponse> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    RealmRoleResponse.class
            );
            return KCResponse.success(response.getBody());

        } catch (HttpClientErrorException.NotFound e) {
            return handleKeyCloakException(AuthzErrorCode.NOT_FOUND_REALM_ROLE, roleName);
        } catch (HttpClientErrorException.Forbidden e) {
            handleKeyCloakException(AuthzErrorCode.FORBIDDEN, roleName);
        } catch (HttpClientErrorException.Unauthorized e) {
            handleKeyCloakException(AuthzErrorCode.UNAUTHORIZED, roleName);
        } catch (Exception e) {
            return handleKeyCloakException(AuthzErrorCode.API_ERROR, roleName);
        }
        return null;
    }

    @Override
    public Boolean isUserExist(String userId) {
        String token = getAccessToken();
        String url = mainURL + AuthzConstans.USER + userId;
        HttpHeaders headers = createAdminHeaders(token);
        ResponseEntity<JsonNode> res = restTemplate.exchange(
                url,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                JsonNode.class
        );

        var user = res.getBody();

        return user != null;
    }

    @Override
    public KCResponse<TokenInfoDTO> decodeToken(String accessToken) {
        return KCResponse.success(tokenDecoder.decode(accessToken));
    }


    public  List<String> getRealmRolesOfUser(String userId) {
        String realmRolesUrl = mainURL + AuthzConstans.USER + userId + AuthzConstans.MAPPING_ROLE;
        String token = getAccessToken();
        HttpHeaders headers = createAdminHeaders(token);
        ResponseEntity<JsonNode> realmResponse = restTemplate.exchange(
                realmRolesUrl,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                JsonNode.class
        );

        List<String> realmRoles = new ArrayList<>();
        if (realmResponse.getBody() != null) {
            for (JsonNode role : realmResponse.getBody()) {
                realmRoles.add(role.get("name").asText());
            }
        }
        return  realmRoles;
    }

    public Map<String, List<String>> getClientRolesOfUser(String userId) {
        String clientsUrl = mainURL + "/clients";
        String token = getAccessToken();
        HttpHeaders headers = createAdminHeaders(token);

        ResponseEntity<JsonNode> clientsResponse = restTemplate.exchange(
                clientsUrl,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                JsonNode.class
        );

        Map<String, List<String>> clientRolesMap = new HashMap<>();
        if (clientsResponse.getBody() != null) {
            for (JsonNode client : clientsResponse.getBody()) {
                String clientId = client.get("id").asText();
                String clientName = client.get("clientId").asText();

                String clientRolesUrl = mainURL + AuthzConstans.USER + userId + AuthzConstans.MAPPING_CLIENT_ROLE+ clientId;

                ResponseEntity<JsonNode> clientRolesResponse = restTemplate.exchange(
                        clientRolesUrl,
                        HttpMethod.GET,
                        new HttpEntity<>(headers),
                        JsonNode.class
                );

                List<String> roles = new ArrayList<>();
                if (clientRolesResponse.getBody() != null) {
                    for (JsonNode r : clientRolesResponse.getBody()) {
                        roles.add(r.get("name").asText());
                    }
                }

                if (!roles.isEmpty()) {
                    clientRolesMap.put(clientName, roles);
                }
            }
        }
        return  clientRolesMap;
    }

    public String getClientRoleId(String clientName, String roleName) {
        try {
            String token = getAccessToken();

            String clientsUrl = mainURL + AuthzConstans.ENQUIRE_CLIENT + clientName;
            HttpHeaders headers = createAdminHeaders(token);
            ResponseEntity<JsonNode> clientsResponse = restTemplate.exchange(
                    clientsUrl,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    JsonNode.class
            );

            if (clientsResponse.getBody() == null || clientsResponse.getBody().isEmpty()) {
                handleKeyCloakException(AuthzErrorCode.CLIENT_ROLE_NOT_FOUND, roleName);
            }

            String clientId = clientsResponse.getBody().get(0).get("id").asText();

            String rolesUrl = mainURL + "/clients/" + clientId + "/roles";

            ResponseEntity<JsonNode> rolesResponse = restTemplate.exchange(
                    rolesUrl,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    JsonNode.class
            );

            if (rolesResponse.getBody() == null || rolesResponse.getBody().isEmpty()) {
                throw new RuntimeException("No roles found for client: " + clientName);
            }

            for (JsonNode role : rolesResponse.getBody()) {
                if (role.get("name").asText().equals(roleName)) {
                    return role.get("id").asText();
                }
            }

            return null;
        } catch (Exception e) {
            throw new RuntimeException("Failed to get client role ID for role: " + roleName + " in client: " + clientName, e);
        }
    }


    @Override
    public KCResponse<RoleResponse> getAllRolesOfUser(String userId) {
        try {
            String token = getAccessToken();
            var res = getUserById(userId);
            if(!res.isSuccess()) {
                return handleKeyCloakException(USER_NOT_FOUND, userId);
            }

            var realmRolesList = getRealmRolesOfUser(userId);

            RoleResponse roleResponse = new RoleResponse();
            roleResponse.setRealmRoles(realmRolesList);

            var clientRolesMap = getClientRolesOfUser(userId);
            roleResponse.setClientRoles(clientRolesMap);

            return KCResponse.success(roleResponse);

        } catch (HttpClientErrorException e) {
            String errorMsg = "";
            try {
                Map<String, Object> errorBody = new ObjectMapper().readValue(e.getResponseBodyAsString(), Map.class);
                errorMsg =  (String) errorBody.get("error_description");
                if(errorMsg == null) {
                    errorMsg = errorBody.get("errorMessage").toString();
                }
            } catch (Exception ex) {
                errorMsg = e.getMessage();
            }
            return  handleKeyCloakException(AuthzErrorCode.TOKEN_INVALID, errorMsg);
        }
    }

    @Override
    public KCResponse<TokenResponse> refreshToken(String refreshToken) {
        try {

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "refresh_token");
            body.add("client_id", props.getClientId());
            body.add("client_secret", props.getClientSecret());
            body.add("refresh_token", refreshToken);

            String url = props.getDomainUrl() + AuthzConstans.REALM + props.getRealmName() + AuthzConstans.PROTOCOL_OPENID_CONNECT + AuthzConstans.TOKEN;
            ResponseEntity<TokenResponse> response =
                    restTemplate.postForEntity(url,
                            new HttpEntity<>(body, headers),
                            TokenResponse.class);
            return KCResponse.success(response.getBody());

        } catch (HttpClientErrorException e) {
            String errorMsg = "";
            try {
                Map<String, Object> errorBody = new ObjectMapper().readValue(e.getResponseBodyAsString(), Map.class);
                errorMsg =  (String) errorBody.get("error_description");
                if(errorMsg == null) {
                    errorMsg = errorBody.get("errorMessage").toString();
                }
            } catch (Exception ex) {
                errorMsg = e.getMessage();
            }
            return  handleKeyCloakException(AuthzErrorCode.TOKEN_INVALID, errorMsg);
        }
    }

    @Override
    public KCResponse<?> logout(String refreshToken) {
        try {
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", props.getClientId());
            body.add("client_secret", props.getClientSecret());
            body.add("refresh_token", refreshToken);

            HttpHeaders headers = createHeaders();
            String url = props.getDomainUrl() + AuthzConstans.REALM + props.getRealmName() + AuthzConstans.PROTOCOL_OPENID_CONNECT + AuthzConstans.LOGOUT;
            restTemplate.postForEntity(
                    url,
                    new HttpEntity<>(body, headers),
                    Void.class
            );
            return KCResponse.success(null);
        } catch (HttpClientErrorException e) {
            String errorMsg = "";
            try {
                Map<String, Object> errorBody = new ObjectMapper().readValue(e.getResponseBodyAsString(), Map.class);
                errorMsg =  (String) errorBody.get("error_description");
                if(errorMsg == null) {
                    errorMsg = errorBody.get("errorMessage").toString();
                }
            } catch (Exception ex) {
                errorMsg = e.getMessage();
            }
            return handleKeyCloakException(AuthzErrorCode.TOKEN_INVALID, errorMsg);
        }
    }


    @Override
    public KCResponse<UserInformation> getUserById(String userId) {

        try {
            String token = getAccessToken();
            String url = mainURL + AuthzConstans.USER + userId;
            HttpHeaders headers = createAdminHeaders(token);
            ResponseEntity<UserInformation> res = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    UserInformation.class
            );

            var user = res.getBody();

            if (user == null) {
                return handleKeyCloakException(AuthzErrorCode.USER_NOT_FOUND, userId);
            }

            var realmRolesList = getRealmRolesOfUser(userId);

            user.setRealmRoles(realmRolesList);

            var clientRolesMap = getClientRolesOfUser(userId);
            user.setClientRoles(clientRolesMap);
            return KCResponse.success(user);
        } catch (HttpClientErrorException e) {
            String errorMsg = "";
            try {
                Map<String, Object> errorBody = new ObjectMapper().readValue(e.getResponseBodyAsString(), Map.class);
                errorMsg =  (String) errorBody.get("error_description");
                if(errorMsg == null) {
                    errorMsg = errorBody.get("errorMessage").toString();
                }
            } catch (Exception ex) {
                errorMsg = e.getMessage();
            }
            if(e.getStatusCode().is4xxClientError()){
                return handleKeyCloakException(AuthzErrorCode.USER_NOT_FOUND, userId);
            }
            return  handleKeyCloakException(AuthzErrorCode.UNKNOWN_ERROR, errorMsg);
        }
    }

    @Override
    public TokenIntrospectionResponse introspectToken(String accessToken) {
        try {
            String url = mainURL + AuthzConstans.PROTOCOL_OPENID_CONNECT
                    + AuthzConstans.TOKEN + AuthzConstans.INTROSPECT;

            HttpHeaders headers = createHeaders();

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", props.getClientId());
            body.add("client_secret", props.getClientSecret());
            body.add("token", accessToken);

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

            ResponseEntity<TokenIntrospectionResponse> response =
                    restTemplate.postForEntity(url, entity, TokenIntrospectionResponse.class);

            TokenIntrospectionResponse result = response.getBody();

            if (result == null || !result.getActive()) {
                handleKeyCloakException(AuthzErrorCode.TOKEN_INVALID, null);
            }

            return result;
        } catch (HttpClientErrorException e) {
            handleKeyCloakException(AuthzErrorCode.TOKEN_INVALID, e.getResponseBodyAsString());
        } catch (HttpServerErrorException e) {
            handleKeyCloakException(AuthzErrorCode.KEYCLOAK_SERVER_ERROR, e.getResponseBodyAsString());
        } catch (ResourceAccessException e) {
            handleKeyCloakException(AuthzErrorCode.KEYCLOAK_CONNECTION_ERROR, e.getMessage());
        } catch (Exception e) {
            handleKeyCloakException(AuthzErrorCode.UNKNOWN_ERROR, e.getMessage());
        }
        return null;
    }


    @Override
    public  KCResponse<UserInformation> updateUserByUserId(String userId, UpdateUserRequest req) {
        try{
            HttpHeaders headers = createAdminHeaders(getAccessToken());
            String url = mainURL + AuthzConstans.USER + userId;
            restTemplate.exchange(
                    url,
                    HttpMethod.PUT,
                    new HttpEntity<>(req, headers),
                    Void.class
            );
            return getUserById(userId);
        } catch (HttpClientErrorException e) {
            String errorMsg = "";
            try {
                Map<String, Object> errorBody = new ObjectMapper().readValue(e.getResponseBodyAsString(), Map.class);
                errorMsg =  (String) errorBody.get("error_description");
                if(errorMsg == null) {
                    errorMsg = errorBody.get("errorMessage").toString();
                }
            } catch (Exception ex) {
                errorMsg = e.getMessage();
            }
            if(e.getStatusCode().value() == 404){
                return handleKeyCloakException(AuthzErrorCode.USER_NOT_FOUND, userId);
            } else if(e.getStatusCode().value() == 409){
                return handleKeyCloakException(AuthzErrorCode.DUPLICATE, errorMsg);
            }
            return  handleKeyCloakException(AuthzErrorCode.UNKNOWN_ERROR, errorMsg);
        }
    }

    @Override
    public KCResponse<UserInformation> updateUserByUserName(String userName, UpdateUserRequest req) {

        var errors = ValidatorUtil.validateFields(req);
        if (!errors.isEmpty()) {
            return handleKeycloakValidation(AuthzErrorCode.VALIDATION_ERROR, errors);
        }
        String userId = "";
        try {
            var res = getUserByUsername(userName);
            if(!res.isSuccess()) {
                return res;
            }
            userId = res.getData().getId();

            HttpHeaders headers =  createAdminHeaders(getAccessToken());
            String url = mainURL + AuthzConstans.USER + userId;
            restTemplate.exchange(
                    url,
                    HttpMethod.PUT,
                    new HttpEntity<>(req, headers),
                    Void.class
            );
            return getUserById(userId);
        } catch (HttpClientErrorException e) {
            String errorMsg = "";
            try {
                Map<String, Object> errorBody = new ObjectMapper().readValue(e.getResponseBodyAsString(), Map.class);
                errorMsg =  (String) errorBody.get("error_description");
                if(errorMsg == null) {
                    errorMsg = errorBody.get("errorMessage").toString();
                }
            } catch (Exception ex) {
                errorMsg = e.getMessage();
            }
            if(e.getStatusCode().value() == 404){
                return handleKeyCloakException(AuthzErrorCode.USER_NOT_FOUND, userName);
            } else if(e.getStatusCode().value() == 409){
                return handleKeyCloakException(AuthzErrorCode.DUPLICATE, errorMsg);
            }
            return  handleKeyCloakException(AuthzErrorCode.UNKNOWN_ERROR, errorMsg);
        }
    }

    @Override
    public KCResponse<UserInformation> enableUserByUserId(String userId) {
        try {
            UpdateUserRequest req = new UpdateUserRequest();
            req.setEnabled(true);
            return updateUserByUserId(userId, req);
        } catch (HttpClientErrorException e) {
            String errorMsg = "";
            try {
                Map<String, Object> errorBody = new ObjectMapper().readValue(e.getResponseBodyAsString(), Map.class);
                errorMsg = (String) errorBody.get("error_description");
                if (errorMsg == null) {
                    errorMsg = errorBody.get("errorMessage").toString();
                }
            } catch (Exception ex) {
                errorMsg = e.getMessage();
            }
            if (e.getStatusCode().value() == 404) {
                return handleKeyCloakException(AuthzErrorCode.USER_NOT_FOUND, userId);
            }
            return handleKeyCloakException(AuthzErrorCode.UNKNOWN_ERROR, errorMsg);
        }
    }

    @Override
    public KCResponse<UserInformation> disableUserByUserId(String userId) {
        try {
            UpdateUserRequest req = new UpdateUserRequest();
            req.setEnabled(false);
            return updateUserByUserId(userId, req);
        } catch (HttpClientErrorException e) {
            String errorMsg = "";
            try {
                Map<String, Object> errorBody = new ObjectMapper().readValue(e.getResponseBodyAsString(), Map.class);
                errorMsg = (String) errorBody.get("error_description");
                if (errorMsg == null) {
                    errorMsg = errorBody.get("errorMessage").toString();
                }
            } catch (Exception ex) {
                errorMsg = e.getMessage();
            }
            if (e.getStatusCode().value() == 404) {
                return handleKeyCloakException(AuthzErrorCode.USER_NOT_FOUND, userId);
            }
            return handleKeyCloakException(AuthzErrorCode.UNKNOWN_ERROR, errorMsg);
        }
    }

    @Override
    public KCResponse<UserInformation> enableUserByUserName(String userName) {
        try {
            UpdateUserRequest req = new UpdateUserRequest();
            req.setEnabled(true);
            return updateUserByUserName(userName, req);
        } catch (HttpClientErrorException e) {
            String errorMsg = "";
            try {
                Map<String, Object> errorBody = new ObjectMapper().readValue(e.getResponseBodyAsString(), Map.class);
                errorMsg = (String) errorBody.get("error_description");
                if (errorMsg == null) {
                    errorMsg = errorBody.get("errorMessage").toString();
                }
            } catch (Exception ex) {
                errorMsg = e.getMessage();
            }
            if (e.getStatusCode().value() == 404) {
                return handleKeyCloakException(AuthzErrorCode.USER_NOT_FOUND, userName);
            }
            return handleKeyCloakException(AuthzErrorCode.UNKNOWN_ERROR, errorMsg);
        }
    }

    @Override
    public KCResponse<UserInformation> disableUserByUserName(String userName) {
        try {
            UpdateUserRequest req = new UpdateUserRequest();
            req.setEnabled(false);
            return updateUserByUserName(userName, req);
        } catch (HttpClientErrorException e) {
            String errorMsg = "";
            try {
                Map<String, Object> errorBody = new ObjectMapper().readValue(e.getResponseBodyAsString(), Map.class);
                errorMsg = (String) errorBody.get("error_description");
                if (errorMsg == null) {
                    errorMsg = errorBody.get("errorMessage").toString();
                }
            } catch (Exception ex) {
                errorMsg = e.getMessage();
            }
            if (e.getStatusCode().value() == 404) {
                return handleKeyCloakException(AuthzErrorCode.USER_NOT_FOUND, userName);
            }
            return handleKeyCloakException(AuthzErrorCode.API_ERROR, errorMsg);
        }
    }

    @Override
    public KCResponse<?> resetPassword(String userId, String newPassword, boolean temporary) {
        try {
            ObjectNode body = objectMapper.createObjectNode();
            body.put("type", "password");
            body.put("value", newPassword);
            body.put("temporary", temporary);

            HttpHeaders headers = createAdminHeaders(getAccessToken());
            String url = mainURL + AuthzConstans.USER + userId + AuthzConstans.RESET_PASSWORD;
            restTemplate.exchange(
                    url,
                    HttpMethod.PUT,
                    new HttpEntity<>(body, headers),
                    Void.class
            );
            return  KCResponse.success(null);

        } catch (HttpClientErrorException e) {
            String errorMsg = "";
            try {
                Map<String, Object> errorBody = new ObjectMapper().readValue(e.getResponseBodyAsString(), Map.class);
                errorMsg = (String) errorBody.get("error_description");
                if (errorMsg == null) {
                    errorMsg = errorBody.get("errorMessage").toString();
                }
            } catch (Exception ex) {
                errorMsg = e.getMessage();
            }
            if (e.getStatusCode().value() == 404) {
                return handleKeyCloakException(AuthzErrorCode.USER_NOT_FOUND, userId);
            }
            return handleKeyCloakException(AuthzErrorCode.UNKNOWN_ERROR, errorMsg);
        }
    }

    @Override
    public KCResponse<?> changePassword(String userName, String oldPassword, String newPassword) {
        try {
            var res = login(userName, oldPassword);
            if(!res.isSuccess()) {
                return res;
            }
            String userId = tokenDecoder.decode(res.getData().getAccessToken()).getUserId();
            return resetPassword(userId, newPassword, false);
        } catch (HttpClientErrorException e) {
            String errorMsg = "";
            try {
                Map<String, Object> errorBody = new ObjectMapper().readValue(e.getResponseBodyAsString(), Map.class);
                errorMsg = (String) errorBody.get("error_description");
                if (errorMsg == null) {
                    errorMsg = errorBody.get("errorMessage").toString();
                }
            } catch (Exception ex) {
                errorMsg = e.getMessage();
            }
            if (e.getStatusCode().value() == 404) {
                return handleKeyCloakException(AuthzErrorCode.USER_NOT_FOUND, userName);
            }
            return handleKeyCloakException(AuthzErrorCode.UNKNOWN_ERROR, errorMsg);
        }
    }
    public KCResponse<UserInformation> removeRealmRoleFromUser(String userId, String roleName) {
        try {
            String adminToken = getAccessToken();
            String roleUrl = mainURL + AuthzConstans.ROLES + roleName;

            HttpHeaders headers = createAdminHeaders(adminToken);
            RoleRepresentation role = restTemplate.exchange(
                    roleUrl,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    RoleRepresentation.class
            ).getBody();

            String url = mainURL + AuthzConstans.USER + userId + AuthzConstans.MAPPING_ROLE;

            restTemplate.exchange(
                    url,
                    HttpMethod.DELETE,
                    new HttpEntity<>(List.of(role), headers),
                    Void.class
            );
            return getUserById(userId);
        } catch (HttpClientErrorException e) {
            String errorMsg = "";
            boolean isUserError = true;
            try {
                Map<String, Object> errorBody = new ObjectMapper().readValue(e.getResponseBodyAsString(), Map.class);
                errorMsg = (String) errorBody.get("error_description");
                if (errorMsg == null) {
                    errorMsg = (String) errorBody.get("errorMessage");
                }
                if (errorMsg == null) {
                    errorMsg = errorBody.get("error").toString();
                    isUserError = false;
                }
            } catch (Exception ex) {
                errorMsg = e.getMessage();
            }
            if (e.getStatusCode().value() == 404) {
                if(isUserError) {
                    return handleKeyCloakException(AuthzErrorCode.USER_NOT_FOUND, userId);
                } else {
                    return handleKeyCloakException(AuthzErrorCode.NOT_FOUND_REALM_ROLE, roleName);
                }

            }
            return handleKeyCloakException(AuthzErrorCode.UNKNOWN_ERROR, errorMsg);
        }
    }

    public KCResponse<UserInformation> removeClientRoleFromUser(String userId, String roleName) {
        try {

            String AdminToken = getAccessToken();
            JsonNode clients = getClient(AdminToken);
            String clientUuid = clients.get(0).get("id").asText();
            String roleUrl = mainURL + AuthzConstans.CLIENT + clientUuid + AuthzConstans.ROLES + roleName;
            HttpHeaders headers = createAdminHeaders(AdminToken);
            RoleRepresentation role = restTemplate.exchange(
                    roleUrl,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    RoleRepresentation.class
            ).getBody();

            String url = mainURL + AuthzConstans.USER + userId + AuthzConstans.MAPPING_CLIENT_ROLE + clientUuid;

            restTemplate.exchange(
                    url,
                    HttpMethod.DELETE,
                    new HttpEntity<>(List.of(role), headers),
                    Void.class
            );

            return  getUserById(userId);
        } catch (HttpClientErrorException e) {
            String errorMsg = "";
            boolean isUserError = true;
            try {
                Map<String, Object> errorBody = new ObjectMapper().readValue(e.getResponseBodyAsString(), Map.class);
                errorMsg = (String) errorBody.get("error_description");
                if (errorMsg == null) {
                    errorMsg = (String) errorBody.get("errorMessage");
                }
                if (errorMsg == null) {
                    errorMsg = errorBody.get("error").toString();
                    isUserError = false;
                }
            } catch (Exception ex) {
                errorMsg = e.getMessage();
            }
            if (e.getStatusCode().value() == 404) {
                if(errorMsg.contains("user")) {
                    return handleKeyCloakException(AuthzErrorCode.USER_NOT_FOUND, userId);
                } else {
                    return handleKeyCloakException(AuthzErrorCode.ROLE_NOT_FOUND, roleName);
                }

            }
            return handleKeyCloakException(AuthzErrorCode.UNKNOWN_ERROR, errorMsg);
        }
    }


    public boolean userHasRealmRole(String userId, String roleName) {
        try{

            String token = getAccessToken();
            HttpHeaders headers = createAdminHeaders(token);
            String url = mainURL + AuthzConstans.USER + userId + AuthzConstans.MAPPING_ROLE;
            ResponseEntity<RoleRepresentation[]> response =
                    restTemplate.exchange(
                            url,
                            HttpMethod.GET,
                            new HttpEntity<>(headers),
                            RoleRepresentation[].class
                    );

            return Arrays.stream(response.getBody())
                    .anyMatch(role -> role.getName().equals(roleName));
        } catch (HttpClientErrorException e) {
            handleKeyCloakException(AuthzErrorCode.API_ERROR, e.getMessage());
        }
        return false;
    }

    public boolean userHasClientRole(String userId, String roleName) {
        try {
            String AdminToken = getAccessToken();
            JsonNode clients = getClient(AdminToken);
            String clientUuid = clients.get(0).get("id").asText();
            HttpHeaders headers = createAdminHeaders(AdminToken);
            String url = mainURL + AuthzConstans.USER + userId + AuthzConstans.MAPPING_CLIENT_ROLE + clientUuid;

            ResponseEntity<RoleRepresentation[]> response =
                    restTemplate.exchange(
                            url,
                            HttpMethod.GET,
                            new HttpEntity<>(headers),
                            RoleRepresentation[].class
                    );

            return Arrays.stream(response.getBody())
                    .anyMatch(role -> role.getName().equals(roleName));
        } catch (HttpClientErrorException e) {
            handleKeyCloakException(AuthzErrorCode.API_ERROR, e.getMessage());
        }
        return false;
    }

}
