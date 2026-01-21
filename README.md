# OAuth2 Configuration

This repository contains an example configuration for integrating OAuth2 authentication with the specified settings. Below are the details of the OAuth2 flow using the `Authorization Code Grant` method, along with `PKCE` from OIDC Debugger

## OAuth2 Configuration Details

- **Authorize URI**: `http://localhost:8080/oauth2/authorize`
- **Client ID**: `react-client`
- **Redirect URI**: `https://oidcdebugger.com/debug`
- **Scope**: `openid`
- **Response Type**: `code`
- **Use PKCE**: YES
- **PKCE Method**: `S256`

## Token Rotation Curl (public client)
```bash
curl --location 'http://localhost:8080/oauth2/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=refresh_token' \
--data-urlencode 'refresh_token=YOUR_REFRESH_TOKEN' \
--data-urlencode 'client_id=react-client' \
--data-urlencode 'code_verifier=YOUR_CODE_VERIFIER'
```

