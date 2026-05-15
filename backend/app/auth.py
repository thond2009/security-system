from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from backend.app.config import settings

security_scheme = HTTPBearer(auto_error=False)


def create_jwt_token(username: str) -> str:
    """Create a JWT access token for a dashboard user."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def verify_ci_token(credentials: HTTPAuthorizationCredentials = Security(security_scheme)):
    """Validate CI API token from Authorization header."""
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    if credentials.credentials != settings.ci_api_token:
        raise HTTPException(status_code=403, detail="Invalid API token")


def verify_jwt_token(credentials: HTTPAuthorizationCredentials = Security(security_scheme)):
    """Validate JWT token for dashboard users."""
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    try:
        payload = jwt.decode(
            credentials.credentials, settings.jwt_secret, algorithms=[settings.jwt_algorithm]
        )
        return payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid or expired token")
