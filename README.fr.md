# Gestionnaire PowerDNS

Une interface web moderne pour gérer les zones et enregistrements PowerDNS, intégrant un contrôle d'accès basé sur les rôles (RBAC) et l'authentification OpenID Connect (OIDC).

*Projet vibe-codé par Gemini Code Assist.*

## Fonctionnalités

- **Piloté par API**: Toutes les manipulations de zones et d'enregistrements sont effectuées exclusivement via l'API PowerDNS.
- **Gestion des Zones**: Création et suppression de zones DNS directes et inverses.
- **Gestion des Enregistrements**: Ajout, modification et suppression d'enregistrements (A, AAAA, CNAME, MX, TXT, etc.) avec validation.
- **Édition Sécurisée**: Les modifications sont mises en attente dans la session et doivent être appliquées explicitement.
- **RBAC**: Système de permissions granulaire avec Utilisateurs, Groupes et Politiques (Propriétaire, Écriture, Lecture, Aucun) par zone ou globalement.
- **Authentification**: Support des utilisateurs locaux (hachage Argon2) et SSO via OIDC.
- **Multilingue**: Support du Français et de l'Anglais. Extensible simplement en ajoutant des fichiers JSON dans le répertoire `locales`.

## Configuration

La configuration se fait via des variables d'environnement ou un fichier `.env`.

### Paramètres Généraux

| Variable | Description | Défaut |
|----------|-------------|---------|
| `PDNS_API_URL` | URL de l'API PowerDNS | `http://localhost:8081/api/v1` |
| `PDNS_API_KEY` | Clé API PowerDNS | `your_powerdns_api_key` |
| `PDNS_SERVER_ID` | ID du serveur PowerDNS | `localhost` |
| `PDNS_TIMEOUT` | Timeout API (secondes) | `10.0` |
| `PDNS_MAX_CONNECTIONS` | Max connexions HTTP | `100` |
| `PDNS_MAX_KEEPALIVE` | Max connexions keepalive | `20` |
| `SECRET_KEY` | Clé secrète pour les sessions | `change-me-in-production` |
| `SESSION_MAX_AGE` | Durée de vie de la session (secondes) | `3600` |
| `DATABASE_URL` | Chaîne de connexion BDD | `sqlite+aiosqlite:///pdnsmgr.db` |

### Configuration du Backend OIDC

Pour activer l'authentification unique (SSO), configurez les variables suivantes. L'application utilise les scopes `openid email profile`.

```ini
OIDC_CLIENT_ID=votre-client-id
OIDC_CLIENT_SECRET=votre-client-secret
OIDC_DISCOVERY_URL=https://votre-provider-oidc/.well-known/openid-configuration
```

L'URI de redirection doit être configurée chez votre fournisseur OIDC comme : `http://votre-domaine/auth/callback`.

### Configuration de la Base de Données

Le projet utilise SQLAlchemy en mode asynchrone. Par défaut, SQLite est utilisé.

* **SQLite** :
    ```ini
    DATABASE_URL=sqlite+aiosqlite:///pdnsmgr.db
    ```
* **PostgreSQL** :
    ```ini
    DATABASE_URL=postgresql+asyncpg://user:password@localhost/dbname
    ```

* **MariaDB / MySQL** :
    ```ini
    DATABASE_URL=mysql+aiomysql://user:password@localhost/dbname
    ```

## Déploiement

1.  **Installation des Dépendances**
    Assurez-vous d'avoir Python 3.8+ installé.
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

2.  **Lancer l'Application**
    ```bash
    uvicorn main:app --host 0.0.0.0 --port 8000
    ```

3.  **Première Connexion**
    Au premier lancement, un utilisateur administrateur par défaut est créé s'il n'existe pas.
    - **Nom d'utilisateur**: `admin`
    - **Mot de passe**: Généré et stocké dans le fichier `admin_password` à la racine.

4.  **Gestion RBAC**
    L'interface d'administration est accessible uniquement aux membres du groupe `admins` via l'URI `/admin`. Elle permet de gérer :
    - Les **Utilisateurs** et leurs groupes.
    - Les **Groupes**.
    - Les **Politiques** d'accès aux zones (support des wildcards).
