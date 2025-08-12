import pytest
from httpx import AsyncClient
from uuid import UUID
from app.main import app
from app.models.user_model import User
from app.schemas.user_schemas import UserResponse
import bcrypt
from fastapi import status
from unittest.mock import AsyncMock

# ---------- Fixtures ----------

@pytest.fixture
async def test_user(db_session):
    """Fixture to create a test user in the database."""
    user = User(
        id=UUID("11111111-1111-1111-1111-111111111111"),
        email="old@example.com",
        nickname="tester",
        first_name="Test",
        last_name="User",
        bio="Old bio",
        is_professional=False,
        role="AUTHENTICATED",
        hashed_password=bcrypt.hashpw("testpassword".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
        email_verified=True
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    yield user

@pytest.fixture
async def auth_headers(monkeypatch, test_user):
    """Fixture to provide headers for a regular authenticated user."""
    async def mock_get_current_user():
        return test_user
    monkeypatch.setattr("app.dependencies.get_current_user", mock_get_current_user)
    return {"Authorization": "Bearer usertoken"}

@pytest.fixture
async def admin_auth_headers(monkeypatch, test_user):
    """Fixture to provide headers for an admin user."""
    async def mock_require_role(roles):
        return User(
            id=UUID("22222222-2222-2222-2222-222222222222"),
            email="admin@example.com",
            nickname="admin",
            role="ADMIN",
            hashed_password=bcrypt.hashpw("adminpassword".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
            email_verified=True
        )
    monkeypatch.setattr("app.dependencies.require_role", mock_require_role)
    return {"Authorization": "Bearer admintoken"}

@pytest.fixture
async def email_service(monkeypatch):
    """Fixture to mock the email service."""
    mock_email_service = AsyncMock()
    mock_email_service.send_professional_status_upgrade_email.return_value = True
    monkeypatch.setattr("app.dependencies.get_email_service", lambda: mock_email_service)
    return mock_email_service

# ---------- Tests ----------

@pytest.mark.asyncio
async def test_update_profile_success(test_user, auth_headers):
    """Test successful partial update of a user's profile."""
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        payload = {
            "first_name": "UpdatedName",
            "bio": "New bio content"
        }
        response = await client.patch("/users/me", json=payload, headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["first_name"] == "UpdatedName"
        assert data["bio"] == "New bio content"
        assert data["id"] == str(test_user.id)
        assert "links" in data

@pytest.mark.asyncio
async def test_update_profile_with_all_fields(test_user, auth_headers):
    """Test successful update of all allowed user profile fields."""
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        payload = {
            "email": "john.doe@example.com",
            "nickname": "john_doe123",
            "first_name": "John",
            "last_name": "Doe",
            "bio": "Experienced software developer specializing in web applications.",
            "profile_picture_url": "https://example.com/profiles/john.jpg",
            "linkedin_profile_url": "https://linkedin.com/in/johndoe",
            "github_profile_url": "https://github.com/johndoe",
            "role": "AUTHENTICATED"
        }
        response = await client.patch("/users/me", json=payload, headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["email"] == "john.doe@example.com"
        assert data["nickname"] == "john_doe123"
        assert data["first_name"] == "John"
        assert data["last_name"] == "Doe"
        assert data["bio"] == payload["bio"]
        assert data["profile_picture_url"] == payload["profile_picture_url"]
        assert data["linkedin_profile_url"] == payload["linkedin_profile_url"]
        assert data["github_profile_url"] == payload["github_profile_url"]
        assert data["role"] == "AUTHENTICATED"
        assert "links" in data

@pytest.mark.asyncio
async def test_upgrade_professional_status_success(test_user, admin_auth_headers, email_service):
    """Test successful upgrade of a user's professional status by an admin."""
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        payload = {"is_professional": True}
        response = await client.patch(
            f"/users/{test_user.id}/professional-status",
            json=payload,
            headers=admin_auth_headers,
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["is_professional"] is True
        assert data["id"] == str(test_user.id)
        assert "links" in data
        email_service.send_professional_status_upgrade_email.assert_called_once()

@pytest.mark.asyncio
async def test_upgrade_professional_status_unauthorized(test_user, auth_headers):
    """Test unauthorized attempt to upgrade professional status with non-admin role."""
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        payload = {"is_professional": True}
        response = await client.patch(
            f"/users/{test_user.id}/professional-status",
            json=payload,
            headers=auth_headers,
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "detail" in response.json()

@pytest.mark.asyncio
async def test_upgrade_professional_status_invalid_payload(test_user, admin_auth_headers):
    """Test attempt to upgrade professional status with invalid payload."""
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        payload = {"is_professional": "yes"}
        response = await client.patch(
            f"/users/{test_user.id}/professional-status",
            json=payload,
            headers=admin_auth_headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert "detail" in response.json()

@pytest.mark.asyncio
async def test_search_users_success(admin_auth_headers, test_user):
    """Test successful search for users by an admin."""
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        response = await client.get("/users/search?query=tester", headers=admin_auth_headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert any(user["nickname"] == "tester" for user in data)
        assert all("links" in user for user in data)