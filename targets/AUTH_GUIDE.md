# Authentication Templates - Quick Reference Guide

## Overview

Your LLM Red Teaming Platform supports **all major authentication types** through a flexible, workflow-based system. This guide shows you how to configure any authentication method for any target application.

---

## Quick Selection Guide

| Authentication Type | Best For | Example |
|---|---|---|
| **None** | Public APIs, mock targets | Demo applications |
| **Bearer Token (Env)** | Static tokens in environment | Azure APIs, OpenAI |
| **Session Cookie** | Web applications, form-based login | Traditional web apps |
| **OAuth 2.0** | Third-party integrations | Google, GitHub, Microsoft |
| **JWT Token** | Modern APIs | REST APIs with JWT |
| **API Key Header** | Simple key-based auth | Weather APIs, Analytics |
| **Basic Auth** | Simple username:password | Legacy systems |

---

## Real-World Configuration Examples

### Example 1: Traditional Web App (Session-Based)

**Target**: HR Chatbot with form-based login and session cookies

```json
{
  "name": "HR Chatbot Session Auth",
  "url": "http://chatbot.company.com:8000/chat",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json"
  },
  "request_template": {
    "message": "{{prompt}}"
  },
  "auth": {
    "type": "session",
    "workflow": {
      "credential_authentication": {
        "enabled": true,
        "method": "POST",
        "url": "http://chatbot.company.com:8000/login",
        "headers": {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        "body": {
          "username": "{{username}}",
          "password": "{{password}}"
        },
        "response_session_id_path": "session_id"
      },
      "next_turn": {
        "enabled": true,
        "method": "POST",
        "url": "http://chatbot.company.com:8000/chat",
        "headers": {
          "Content-Type": "application/json",
          "Cookie": "session={{session_id}}"
        },
        "body": {
          "message": "{{prompt}}"
        },
        "response_message_path": "response"
      }
    }
  },
  "timeout_seconds": 120
}
```

**Environment Setup**:
```bash
export CHATBOT_USERNAME=testuser
export CHATBOT_PASSWORD=testpass123
```

---

### Example 2: Modern REST API (JWT Token)

**Target**: LLM service using JWT authentication

```json
{
  "name": "LLM Service JWT Auth",
  "url": "https://llm-api.example.com/inference",
  "method": "POST",
  "auth": {
    "type": "session",
    "workflow": {
      "credential_authentication": {
        "enabled": true,
        "method": "POST",
        "url": "https://llm-api.example.com/v1/auth/login",
        "headers": {
          "Content-Type": "application/json"
        },
        "body": {
          "email": "{{username}}",
          "password": "{{password}}"
        },
        "access_token_path": "data.token"
      },
      "next_turn": {
        "enabled": true,
        "method": "POST",
        "url": "https://llm-api.example.com/v1/inference",
        "headers": {
          "Content-Type": "application/json",
          "Authorization": "Bearer {{access_token}}"
        },
        "body": {
          "prompt": "{{prompt}}",
          "model": "gpt-4",
          "temperature": 0.7
        },
        "response_message_path": "data.response"
      }
    }
  },
  "timeout_seconds": 60
}
```

---

### Example 3: OAuth2 Protected API

**Target**: Third-party LLM platform with OAuth2 client credentials

```json
{
  "name": "OAuth2 LLM Service",
  "url": "https://api.provider.com/chat",
  "method": "POST",
  "auth": {
    "type": "session",
    "workflow": {
      "credential_authentication": {
        "enabled": true,
        "method": "POST",
        "url": "https://oauth.provider.com/oauth/token",
        "headers": {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        "body": {
          "grant_type": "client_credentials",
          "client_id": "{{username}}",
          "client_secret": "{{password}}"
        },
        "access_token_path": "access_token"
      },
      "next_turn": {
        "enabled": true,
        "method": "POST",
        "url": "https://api.provider.com/v1/chat/completions",
        "headers": {
          "Content-Type": "application/json",
          "Authorization": "Bearer {{access_token}}"
        },
        "body": {
          "messages": [
            {
              "role": "user",
              "content": "{{prompt}}"
            }
          ]
        },
        "response_message_path": "choices[0].message.content"
      }
    }
  },
  "timeout_seconds": 120
}
```

---

### Example 4: Static API Key in Headers

**Target**: Public API with static API key authentication

```json
{
  "name": "API Key Protected Service",
  "url": "https://api.service.com/v1/chat",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json",
    "X-API-Key": "YOUR_STATIC_API_KEY_HERE"
  },
  "request_template": {
    "message": "{{prompt}}"
  },
  "auth": {
    "type": "none"
  },
  "timeout_seconds": 60
}
```

---

### Example 5: Environment Variable Bearer Token

**Target**: Azure OpenAI or similar service with env-based tokens

```json
{
  "name": "Azure OpenAI Service",
  "url": "https://your-resource.openai.azure.com/openai/deployments/your-model/chat/completions",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json"
  },
  "request_template": {
    "messages": [
      {
        "role": "user",
        "content": "{{prompt}}"
      }
    ]
  },
  "auth": {
    "type": "bearer",
    "token_env": "AZURE_OPENAI_API_KEY"
  },
  "timeout_seconds": 120
}
```

**Environment Setup**:
```bash
export AZURE_OPENAI_API_KEY="your-key-here"
```

---

### Example 6: Complex Multi-Step Auth

**Target**: Enterprise API requiring login + session + refresh token

```json
{
  "name": "Enterprise LLM Platform",
  "url": "https://enterprise.company.com/api/v2/chat",
  "method": "POST",
  "auth": {
    "type": "session",
    "workflow": {
      "credential_authentication": {
        "enabled": true,
        "method": "POST",
        "url": "https://enterprise.company.com/api/v2/auth/login",
        "headers": {
          "Content-Type": "application/json"
        },
        "body": {
          "username": "{{username}}",
          "password": "{{password}}",
          "app_version": "1.0"
        },
        "access_token_path": "result.access_token",
        "response_session_id_path": "result.refresh_token"
      },
      "next_turn": {
        "enabled": true,
        "method": "POST",
        "url": "https://enterprise.company.com/api/v2/chat/message",
        "headers": {
          "Content-Type": "application/json",
          "Authorization": "Bearer {{access_token}}",
          "X-Refresh-Token": "{{session_id}}"
        },
        "body": {
          "message": "{{prompt}}",
          "conversation_id": "{{conversation_id}}"
        },
        "response_message_path": "data.reply"
      }
    }
  },
  "timeout_seconds": 120
}
```

---

## Debugging & Troubleshooting

### Issue: "access_token_path not found in response"

**Solution**: Verify the JSON path in your response
```bash
# Test the login endpoint directly
curl -X POST https://your-api.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"pass"}' | jq .
```

Update `access_token_path` to match the actual response structure.

### Issue: "Session cookie not being sent"

**Solution**: Verify cookie format in headers
```json
"headers": {
  "Cookie": "session={{session_id}}"
}
```

Some APIs may use different formats:
- `session={{session_id}}`
- `auth_token={{session_id}}`
- `SESSIONID={{session_id}}`

### Issue: "401 Unauthorized on next_turn requests"

**Solution**: Check that:
1. `credential_authentication` response contains the token/session
2. `access_token_path` or `response_session_id_path` matches actual response
3. Header name in `next_turn` matches what API expects

---

## Applying Templates to Your Target

### Step-by-Step Process:

1. **Identify your target's auth method** from the selection guide
2. **Find matching template** in `AUTH_TEMPLATES.json`
3. **Copy the template** and customize:
   - Replace `url` with your actual endpoints
   - Update header names if they differ
   - Adjust response paths to match your API's JSON structure
   - Set `username`/`password` variables
4. **Test the auth flow**:
   ```bash
   # Manually test login endpoint
   curl -X POST your-login-url \
     -H "Content-Type: application/json" \
     -d '{"username":"test","password":"pass"}'
   ```
5. **Verify response paths** match your actual API response
6. **Run a scan** to validate the configuration

---

## Template Variable Reference

| Variable | Set By | Example |
|---|---|---|
| `{{prompt}}` | Platform automatically | "Generate a password reset email" |
| `{{username}}` | Scan request or environment | "testuser" |
| `{{password}}` | Scan request or environment | "securepass123" |
| `{{session_id}}` | Extracted from credential_authentication | Extracted from login response |
| `{{access_token}}` | Extracted from credential_authentication | JWT token from auth endpoint |
| `{{conversation_id}}` | Platform automatically | UUID for conversation tracking |

---

## Path Extraction Examples

```json
"response_message_path": "message"
→ Extracts: response.message

"response_message_path": "data.response.text"
→ Extracts: response.data.response.text

"response_message_path": "choices[0].message.content"
→ Extracts: response.choices[0].message.content

"access_token_path": "result.token.jwt"
→ Extracts: response.result.token.jwt
```

---

## Best Practices

✅ **DO**:
- Store sensitive credentials in environment variables
- Use descriptive names for your target configs
- Document custom header requirements
- Test auth flow before running full scan
- Use specific path extraction (avoid top-level fields)

❌ **DON'T**:
- Hardcode passwords in config files
- Use overly broad response paths
- Ignore API rate limiting (adjust timeout_seconds)
- Skip testing the login flow
- Forget to set required environment variables

---

## File Organization

```
targets/
├── AUTH_TEMPLATES.json              ← All templates (reference)
├── vulnerable-chatbot-session.json  ← Your custom config (session auth)
├── internal-hr-chatbot.json         ← Another config (no auth)
├── api-oauth2.json                  ← OAuth2 example
└── api-jwt.json                     ← JWT example
```

Save your target configurations to `targets/` folder following the pattern above.
