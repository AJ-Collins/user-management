import pytest
from httpx import AsyncClient
from uuid import UUID
from app.main import app
from app.models import User

# ---------- Fixtures ----------

@pytest.fixture
async def test_user(db_session):
    user = User(
        id=UUID("11111111-1111-1111-1111-111111111111"),
        email="old@example.com",
        nickname="tester",
        first_name="Test",
        last_name="User",
        bio="Old bio",
        is_professional=False,
        role="AUTHENTICATED"
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    yield user

@pytest.fixture
async def auth_headers():
    return {"Authorization": "Bearer usertoken"}

@pytest.fixture
async def admin_auth_headers():
    return {"Authorization": "Bearer admintoken"}


# ---------- Tests ----------

@pytest.mark.asyncio
async def test_update_profile_success(test_user, auth_headers):
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        payload = {
            "first_name": "UpdatedName",
            "bio": "New bio content"
        }
        response = await client.patch("/users/me", json=payload, headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["first_name"] == "UpdatedName"
        assert data["bio"] == "New bio content"


@pytest.mark.asyncio
async def test_update_profile_with_all_fields(test_user, auth_headers):
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
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "john.doe@example.com"
        assert data["role"] == "AUTHENTICATED"


@pytest.mark.asyncio
async def test_update_profile_invalid_payload(auth_headers):
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        payload = {"additional_fields": {"jgghj"}}  # Invalid JSON
        response = await client.patch("/users/me", json=payload, headers=auth_headers)
        assert response.status_code == 422


@pytest.mark.asyncio
async def test_upgrade_professional_status_success(test_user, admin_auth_headers, monkeypatch):
    async def fake_send_email(user, upgraded_by):
        return True
    monkeypatch.setattr("app.api.email.EmailService.send_professional_status_upgrade_email", fake_send_email)

    async with AsyncClient(app=app, base_url="http://testserver") as client:
        payload = {"is_professional": True}
        response = await client.patch(
            f"/users/{test_user.id}/professional-status",
            json=payload,
            headers=admin_auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_professional"] is True


@pytest.mark.asyncio
async def test_upgrade_professional_status_unauthorized(test_user, auth_headers):
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        payload = {"is_professional": True}
        response = await client.patch(
            f"/users/{test_user.id}/professional-status",
            json=payload,
            headers=auth_headers,
        )
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_upgrade_professional_status_invalid_payload(test_user, admin_auth_headers):
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        payload = {"is_professional": "yes"}  # Invalid type
        response = await client.patch(
            f"/users/{test_user.id}/professional-status",
            json=payload,
            headers=admin_auth_headers,
        )
        assert response.status_code == 422


@pytest.mark.asyncio
async def test_search_users_success(admin_auth_headers):
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        response = await client.get("/users/search?query=John", headers=admin_auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)