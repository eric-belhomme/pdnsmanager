# PowerDNS Manager

A modern, web-based interface for managing PowerDNS zones and records, featuring Role-Based Access Control (RBAC) and OpenID Connect (OIDC) authentication.

*Project vibe-coded by Gemini Code Assist.*

## Features

- **API Driven**: All zone and record manipulations are performed exclusively via the PowerDNS API.
- **Zone Management**: Create and delete forward and reverse DNS zones.
- **Record Management**: Add, edit, and delete DNS records (A, AAAA, CNAME, MX, TXT, etc.) with validation.
- **Safe Editing**: Changes are staged in a session and must be explicitly applied, allowing for review before commitment.
- **RBAC**: Granular permission system with Users, Groups, and Policies (Owner, Write, Read, None) per zone or globally.
- **Authentication**: Support for local users (Argon2 hashing) and SSO via OIDC.
- **Multi-language**: English and French support. Easily extensible by adding JSON files in the `locales` directory.

## Configuration

Configuration is handled via environment variables or a `.env` file.

### General Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `PDNS_API_URL` | URL to PowerDNS API | `http://localhost:8081/api/v1` |
| `PDNS_API_KEY` | PowerDNS API Key | `your_powerdns_api_key` |
| `PDNS_SERVER_ID` | PowerDNS Server ID | `localhost` |
| `PDNS_TIMEOUT` | API Timeout (seconds) | `10.0` |
| `PDNS_MAX_CONNECTIONS` | Max HTTP connections | `100` |
| `PDNS_MAX_KEEPALIVE` | Max keepalive connections | `20` |
| `SECRET_KEY` | Secret key for sessions | `change-me-in-production` |
| `SESSION_MAX_AGE` | Session duration (seconds) | `3600` |
| `DATABASE_URL` | Database connection string | `sqlite+aiosqlite:///rbac.db` |

### OIDC Backend Configuration

To enable Single Sign-On (SSO), configure the following variables. The application uses the `openid email profile` scopes.

```ini
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_DISCOVERY_URL=https://your-oidc-provider/.well-known/openid-configuration
```

The redirect URI should be configured in your OIDC provider as: `http://your-domain/auth/callback`.

### Database Configuration

The project uses SQLAlchemy with asyncio. By default, it uses SQLite.

* **SQLite** :
    ```ini
    DATABASE_URL=sqlite+aiosqlite:///rbac.db
    ```

* **PostgreSQL** :
    ```ini
    DATABASE_URL=postgresql+asyncpg://user:password@localhost/dbname
    ```

* **MariaDB / MySQL** :
    ```ini
    DATABASE_URL=mysql+aiomysql://user:password@localhost/dbname
    ```

## Deployment

1.  **Install Dependencies**
    Ensure you have Python 3.8+ installed.
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

2.  **Run the Application**
    ```bash
    uvicorn main:app --host 0.0.0.0 --port 8000
    ```

3.  **First Login**
    On the first run, a default admin user is created if it doesn't exist.
    - **Username**: `admin`
    - **Password**: Generated and stored in `admin_password` file at the root.

4.  **RBAC Management**
    The administration interface is accessible only to members of the `admins` group via the `/admin` URI. It allows managing:
    - **Users** and their groups.
    - **Groups**.
    - **Policies** for zone access (wildcard support).