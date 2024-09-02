
```markdown
# Beeper API Documentation

---

## 1. Start Login

**Endpoint:** `/user/login`  
**Method:** `POST`  
**Description:** Initiates the login process by generating a login request.

### Request Headers

```plaintext
Authorization: Bearer BEEPER-PRIVATE-API-PLEASE-DONT-USE
```

### Request Body

```json
{}
```

### Response

```plaintext
HTTP 200 OK
{
  "request": "string",
  "type": ["string"],
  "expires": "timestamp"
}
```

---

## 2. Send Login Email

**Endpoint:** `/user/login/email`  
**Method:** `POST`  
**Description:** Sends a login email with a code to the user's email address.

### Request Headers

```plaintext
Authorization: Bearer BEEPER-PRIVATE-API-PLEASE-DONT-USE
Content-Type: application/json
```

### Request Body

```json
{
  "request": "string",
  "email": "user@example.com"
}
```

### Response

```plaintext
HTTP 200 OK
```

---

## 3. Send Login Code

**Endpoint:** `/user/login/response`  
**Method:** `POST`  
**Description:** Verifies the login code sent to the user's email or SMS.

### Request Headers

```plaintext
Authorization: Bearer BEEPER-PRIVATE-API-PLEASE-DONT-USE
Content-Type: application/json
```

### Request Body

```json
{
  "request": "string",
  "response": "string"
}
```

### Response

```plaintext
HTTP 200 OK
{
  "token": "string",
  "whoami": { ... }  // Details about the user
}
```

---

## 4. Who Am I

**Endpoint:** `/whoami`  
**Method:** `GET`  
**Description:** Retrieves details about the authenticated user, including bridges and other data.

### Request Headers

```plaintext
Authorization: Bearer <token>
```

### Response

```plaintext
HTTP 200 OK
{
  "user": { ... },   // User details
  "userInfo": { ... } // Additional user information
}
```

---

## 5. Post Bridge State

**Endpoint:** `/bridgebox/{username}/bridge/{bridge_name}/bridge_state`  
**Method:** `POST`  
**Description:** Updates the state of a specified bridge, such as starting or stopping it.

### Request Headers

```plaintext
Authorization: Bearer <asToken>
Content-Type: application/json
```

### Request Body

```json
{
  "stateEvent": "string",  // State event like "start" or "stop"
  "reason": "string",
  "isSelfHosted": true/false,
  "bridgeType": "string"
}
```

### Response

```plaintext
HTTP 200 OK: State update was successful.
HTTP 500 Internal Server Error: Server error, request failed.
```

---

## 6. Start Bridge

**Endpoint:** `/bridge/{bridgeName}/start`  
**Method:** `POST`  
**Description:** Starts a bridge that has been previously configured.

### Request Headers

```plaintext
Authorization: Bearer <token>
```

### Response

```plaintext
HTTP 200 OK: The bridge was successfully started.
HTTP 500 Internal Server Error: Server error, start failed.
```

---

## 7. Stop Bridge

**Endpoint:** `/bridge/{bridgeName}/stop`  
**Method:** `POST`  
**Description:** Stops a running bridge.

### Request Headers

```plaintext
Authorization: Bearer <token>
```

### Response

```plaintext
HTTP 200 OK: The bridge was successfully stopped.
HTTP 500 Internal Server Error: Server error, stop failed.
```

---

## 8. Delete Bridge

**Endpoint:** `/bridge/{bridgeName}`  
**Method:** `DELETE`  
**Description:** Deletes a bridge and cleans up its associated resources.

### Request Headers

```plaintext
Authorization: Bearer <token>
```

### Response

```plaintext
HTTP 204 No Content: The bridge was successfully deleted.
HTTP 500 Internal Server Error: Server error, deletion failed.
```

---

## 9. Password Reset

**Endpoint:** `/_matrix/client/v3/account/password`  
**Method:** `POST`  
**Description:** Allows a user to reset their password.

### Request Headers

```plaintext
Authorization: Bearer <access_token>
Content-Type: application/json
```

### Request Body

```json
{
  "auth": {
    "type": "org.matrix.login.jwt",
    "token": "string",
    "session": "string"
  },
  "new_password": "string",
  "logout_devices": false
}
```

### Response

```plaintext
HTTP 200 OK: Password reset was successful.
HTTP 500 Internal Server Error: Server error, request failed.
```
