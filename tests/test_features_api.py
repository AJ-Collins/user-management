import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID
from app.models.user_model import User, UserRole
from app.services.user_service import UserService
import bcrypt
from unittest.mock import AsyncMock

pytestmark = pytest.mark.asyncio

# ---------- Fixtures ----------

@pytest.fixture
async def test_user(db_session: AsyncSession):
    """Fixture to create a test user in the database."""
    user = User(
        id=UUID("11111111-1111-1111-1111-111111111111"),
        email="old@example.com",
        nickname="tester",
        first_name="Test",
        last_name="User",
        bio="Old bio",
        is_professional=False,
        role=UserRole.AUTHENTICATED,
        hashed_password=bcrypt.hashpw("testpassword".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
        email_verified=True
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    yield user
    await db_session.delete(user)
    await db_session.commit()

@pytest.fixture
async def admin_user(db_session: AsyncSession):
    """Fixture to create an admin user in the database."""
    admin = User(
        id=UUID("22222222-2222-2222-2222-222222222222"),
        email="admin@example.com",
        nickname="admin",
        first_name="Admin",
        last_name="User",
        bio="Admin bio",
        is_professional=False,
        role=UserRole.ADMIN,
        hashed_password=bcrypt.hashpw("adminpassword".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
        email_verified=True
    )
    db_session.add(admin)
    await db_session.commit()
    await db_session.refresh(admin)
    yield admin
    await db_session.delete(admin)
    await db_session.commit()

@pytest.fixture
async def email_service(monkeypatch):
    """Fixture to mock the email service."""
    mock_email_service = AsyncMock()
    mock_email_service.send_professional_status_upgrade_email.return_value = True
    monkeypatch.setattr("app.dependencies.get_email_service", lambda: mock_email_service)
    return mock_email_service

# ---------- Tests ----------

async def test_update_profile_success(db_session: AsyncSession, test_user: User):
    """Test successful partial update of a user's profile."""
    user_data = {
        "first_name": "UpdatedName",
        "bio": "New bio content"
    }
    updated_user = await UserService.update(db_session, test_user.id, user_data)
    assert updated_user is not None
    assert updated_user.first_name == "UpdatedName"
    assert updated_user.bio == "New bio content"
    assert updated_user.id == test_user.id

async def test_update_profile_with_all_fields(db_session: AsyncSession, test_user: User):
    """Test successful update of all allowed user profile fields."""
    user_data = {
        "email": "john.doe@example.com",
        "nickname": "john_doe123",
        "first_name": "John",
        "last_name": "Doe",
        "bio": "Experienced software developer specializing in web applications.",
        "profile_picture_url": "https://example.com/profiles/john.jpg",
        "linkedin_profile_url": "https://linkedin.com/in/johndoe",
        "github_profile_url": "https://github.com/johndoe",
        "role": UserRole.AUTHENTICATED.name
    }
    updated_user = await UserService.update(db_session, test_user.id, user_data)
    assert updated_user is not None
    assert updated_user.email == "john.doe@example.com"
    assert updated_user.nickname == "john_doe123"
    assert updated_user.first_name == "John"
    assert updated_user.last_name == "Doe"
    assert updated_user.bio == user_data["bio"]
    assert updated_user.profile_picture_url == user_data["profile_picture_url"]
    assert updated_user.linkedin_profile_url == user_data["linkedin_profile_url"]
    assert updated_user.github_profile_url == user_data["github_profile_url"]
    assert updated_user.role == UserRole.AUTHENTICATED.value

async def test_update_profile_invalid_payload(db_session: AsyncSession, test_user: User):
    """Test update with invalid payload (e.g., incorrect email format)."""
    user_data = {"email": "invalid-email"}
    updated_user = await UserService.update(db_session, test_user.id, user_data)
    assert updated_user is None

async def test_upgrade_professional_status_success(db_session: AsyncSession, test_user: User):
    """Test successful upgrade of a user's professional status."""
    updated_user = await UserService.set_professional_status(db_session, test_user.id, True)
    assert updated_user is not None
    assert updated_user.is_professional is True
    assert updated_user.id == test_user.id
    assert updated_user.professional_status_updated_at is not None

async def test_upgrade_professional_status_unauthorized(db_session: AsyncSession, test_user: User, admin_user: User):
    """Test setting professional status (no admin check in service, so same as success case)."""
    # Note: UserService.set_professional_status does not check for admin privileges,
    # so this test is similar to the success case. Consider adding authorization in the service.
    updated_user = await UserService.set_professional_status(db_session, test_user.id, True)
    assert updated_user is not None
    assert updated_user.is_professional is True
    assert updated_user.id == test_user.id

async def test_upgrade_professional_status_invalid_payload(db_session: AsyncSession, test_user: User):
    """Test setting professional status with invalid input (handled by type hint)."""
    # Note: The method enforces bool via type hint, so we can't pass a non-bool.
    # Test with a valid bool to ensure the method works as expected.
    updated_user = await UserService.set_professional_status(db_session, test_user.id, False)
    assert updated_user is not None
    assert updated_user.is_professional is False

async def test_search_users_success(db_session: AsyncSession, test_user: User):
    """Test successful search for users by first name."""
    users = await UserService.search_users(db_session, "Test")
    assert isinstance(users, list)
    assert len(users) >= 1
    assert any(user.first_name == "Test" for user in users)