# FastAPI OAuth2 Authentication Application

This is a FastAPI-based application implementing OAuth2 authentication with Google and GitHub, along with basic user registration and login functionalities. It also provides routes to get all registered users.

## Features

- OAuth2 authentication with Google and GitHub.
- User registration.
- User login with JWT token generation.
- Fetch all registered users.

## Prerequisites

- Python 3.11+
- FastAPI
- SQLModel
- HTTPX
- Uvicorn
- python-dotenv

## Installation

1. **Clone the repository:**

   ```
   git clone https://github.com/devmianharoon/authentication-fastapi.git
   cd fastapi-oauth2-authentication

   ```

2. **Install the dependencies:**
   `poetry install `

3. **Create and activate a virtual environment:**
   `poetry shell`

4. **Create a .env file in the root directory and add the following variables:**

    ```ALGORITHM=HS256
    SECRET_KEY=your_secret_key
    GITHUB_CLIENT_ID=your_github_client_id
    GITHUB_CLIENT_SECRET=your_github_client_secret
    GITHUB_REDIRECT_URI=your_github_redirect_uri
    GOOGLE_CLIENT_ID=your_google_client_id
    GOOGLE_CLIENT_SECRET=your_google_client_secret
    GOOGLE_PROJECT_ID=your_google_project_id
    GOOGLE_REDIRECT_URI=your_google_redirect_uri
    GOOGLE_TOKEN_URL=https://oauth2.googleapis.com/token
    ```
5. **Run the application:**
    ```poetry run dev```

6. **Usage**
    ## Endpoints:

    # Google Login:
       - GET /google-login - Redirects to Google OAuth2 login page.
       - GET /auth/google - Callback URL for Google authentication.

    # GitHub Login:
       - GET /github-login - Redirects to GitHub OAuth2 login page.
       - GET /auth/callback - Callback URL for GitHub authentication.

    # User Registration:
       - POST /resister - Register a new user.

    # User Login:
       - POST /login - Login with username and password.

    # Get All Users:

       - GET /users - Retrieve all registered users.

## API Examples

### User Registration
```bash
curl -X POST https://authentication-fastapi.onrender.com/resister \
  -H "Content-Type: application/json" \
  -d '{
    "userName": "testuser",
    "name": "Test User",
    "email": "milanbhuyan7@gmail.com",
    "password": "password123"
  }'
```

### User Login
```bash
curl -X POST https://authentication-fastapi.onrender.com/login \
  -d "username=testuser&password=password123"
```

### Get All Users
```bash
curl -H "Authorization: Bearer <your_access_token>" \
  https://authentication-fastapi.onrender.com/users
```

### Google OAuth Login
1. Visit `GET /google-login` to redirect to Google OAuth.
2. After authorization, Google redirects to `GET /auth/google?code=<code>` which returns an access token.

### GitHub OAuth Login
1. Visit `GET /github-login` to redirect to GitHub OAuth.
2. After authorization, GitHub redirects to `GET /auth/callback?code=<code>` which returns an access token.

### MCP JSON-RPC Endpoints
The app supports MCP-compatible JSON-RPC 2.0 endpoints over HTTP at `POST /mcp`.

#### Send Email
```json
{
  "jsonrpc": "2.0",
  "method": "gmail.send_email",
  "params": {
    "to": "milanbhuyan7@gmail.com",
    "subject": "Test Subject",
    "body": "Test Body"
  },
  "id": 1
}
```

#### List Labels
```json
{
  "jsonrpc": "2.0",
  "method": "gmail.list_labels",
  "params": {},
  "id": 2
}
```

#### Search Messages
```json
{
  "jsonrpc": "2.0",
  "method": "gmail.search_messages",
  "params": {
    "query": "subject:test"
  },
  "id": 3
}
```

#### Get Message
```json
{
  "jsonrpc": "2.0",
  "method": "gmail.get_message",
  "params": {
    "id": "message_id_here"
  },
  "id": 4
}
```

**Contributing**

    Contributions are welcome! Please open an issue or submit a pull request."# authentication-fastapi"  
 
