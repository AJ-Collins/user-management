from builtins import Exception, bool, classmethod, int, str
from datetime import datetime, timezone
import secrets
from typing import Optional, Dict, List
from pydantic import ValidationError
from sqlalchemy import func, null, update, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from app.dependencies import get_email_service, get_settings
from app.models.user_model import User
from app.schemas.user_schemas import UserCreate, UserUpdate
from app.utils.nickname_gen import generate_nickname
from app.utils.security import generate_verification_token, hash_password, verify_password
from uuid import UUID
from app.services.email_service import EmailService
from app.models.user_model import UserRole
import logging

settings = get_settings()
logger = logging.getLogger(__name__)

class UserService:
    @classmethod
    async def _execute_query(cls, session: AsyncSession, query):
        try:
            result = await session.execute(query)
            await session.commit()
            return result
        except SQLAlchemyError as e:
            logger.error(f"Database error: {e}")
            await session.rollback()
            return None

    @classmethod
    async def _fetch_user(cls, session: AsyncSession, **filters) -> Optional[User]:
        query = select(User)

        # Special case for email filter
        if "email" in filters:
            email = filters.pop("email")
            query = query.where(func.lower(User.email) == email.lower())

        for key, value in filters.items():
            query = query.where(getattr(User, key) == value)

        result = await cls._execute_query(session, query)
        return result.scalars().first() if result else None

    @classmethod
    async def get_by_id(cls, session: AsyncSession, user_id: UUID) -> Optional[User]:
        return await cls._fetch_user(session, id=user_id)

    @classmethod
    async def get_by_nickname(cls, session: AsyncSession, nickname: str) -> Optional[User]:
        return await cls._fetch_user(session, nickname=nickname)

    @classmethod
    async def get_by_email(cls, session: AsyncSession, email: str) -> Optional[User]:
        return await cls._fetch_user(session, email=email)

    @classmethod
    async def create(cls, session: AsyncSession, user_data: Dict[str, str], email_service: EmailService) -> Optional[User]:
        try:
            validated_data = UserCreate(**user_data).model_dump()
            email = validated_data['email']
            password = validated_data.pop('password')
            nickname = validated_data.get('nickname')

            # Check if email already exists
            if await cls.get_by_email(session, email):
                raise ValueError("Email already exists.")

            # Handle nickname conflicts
            if nickname:
                if await cls.get_by_nickname(session, nickname):
                    raise ValueError("Nickname already exists.")
            else:
                nickname = generate_nickname()
                while await cls.get_by_nickname(session, nickname):
                    nickname = generate_nickname()

            # Create new user
            validated_data['hashed_password'] = hash_password(password)
            new_user = User(**validated_data)
            new_user.nickname = nickname

            user_count = await cls.count(session)
            new_user.role = UserRole.ADMIN if user_count == 0 else UserRole.ANONYMOUS

            if new_user.role == UserRole.ADMIN:
                new_user.email_verified = True
            else:
                new_user.verification_token = generate_verification_token()

            session.add(new_user)
            await session.commit()
            await session.refresh(new_user)

            if new_user.role != UserRole.ADMIN:
                await email_service.send_verification_email(new_user)

            return new_user

        except ValidationError as e:
            logger.error(f"Validation error during user creation: {e}")
            raise ValueError("Invalid input data.")
        except ValueError as ve:
            logger.error(str(ve))
            raise ve


    @classmethod
    async def update(cls, session: AsyncSession, user_id: UUID, update_data: Dict[str, str]) -> Optional[User]:
        try:
            # validated_data = UserUpdate(**update_data).dict(exclude_unset=True)
            validated_data = UserUpdate(**update_data).model_dump(exclude_unset=True)

            if 'password' in validated_data:
                validated_data['hashed_password'] = hash_password(validated_data.pop('password'))
            query = update(User).where(User.id == user_id).values(**validated_data).execution_options(synchronize_session="fetch")
            await cls._execute_query(session, query)
            updated_user = await cls.get_by_id(session, user_id)
            if updated_user:
                await session.refresh(updated_user) 
                logger.info(f"User {user_id} updated successfully.")
                return updated_user
            else:
                logger.error(f"User {user_id} not found after update attempt.")
            return None
        except Exception as e:  # Broad exception handling for debugging
            logger.error(f"Error during user update: {e}")
            return None

    @classmethod
    async def delete(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if not user:
            logger.info(f"User with ID {user_id} not found.")
            return False
        await session.delete(user)
        await session.commit()
        return True

    @classmethod
    async def list_users(cls, session: AsyncSession, skip: int = 0, limit: int = 10) -> List[User]:
        query = select(User).offset(skip).limit(limit)
        result = await cls._execute_query(session, query)
        return result.scalars().all() if result else []

    @classmethod
    async def register_user(cls, session: AsyncSession, user_data: Dict[str, str], get_email_service) -> Optional[User]:
        return await cls.create(session, user_data, get_email_service)
    

# login user
    @classmethod
    async def login_user(cls, session: AsyncSession, email: str, password: str) -> User:
        user = await cls.get_by_email(session, email)
        if not user:
            raise ValueError("Incorrect email or password.")

    # ✅ Prioritize lock over email verification
        if user.is_locked:
            raise ValueError("Account is locked due to too many failed login attempts.")

        if not user.email_verified:
            raise ValueError("Email not verified.")

        if not verify_password(password, user.hashed_password):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.max_login_attempts:
                user.is_locked = True
            session.add(user)
            await session.commit()
            raise ValueError("Incorrect email or password.")

        user.failed_login_attempts = 0
        user.last_login_at = datetime.now(timezone.utc)
        session.add(user)
        await session.commit()
        return user

# is account locked
    @classmethod
    async def is_account_locked(cls, session: AsyncSession, email: str) -> bool:
        user = await cls.get_by_email(session, email)
        return user.is_locked if user else False


    @classmethod
    async def reset_password(cls, session: AsyncSession, user_id: UUID, new_password: str) -> bool:
        hashed_password = hash_password(new_password)
        user = await cls.get_by_id(session, user_id)
        if user:
            user.hashed_password = hashed_password
            user.failed_login_attempts = 0  # Resetting failed login attempts
            user.is_locked = False  # Unlocking the user account, if locked
            session.add(user)
            await session.commit()
            return True
        return False

    @classmethod
    async def verify_email_with_token(cls, session: AsyncSession, user_id: UUID, token: str) -> bool:
        user = await cls.get_by_id(session, user_id)
        if user and user.verification_token == token:
            user.email_verified = True
            user.verification_token = None  # Clear the token once used
            user.role = UserRole.AUTHENTICATED
            session.add(user)
            await session.commit()
            return True
        return False

    @classmethod
    async def count(cls, session: AsyncSession) -> int:
        """
        Count the number of users in the database.

        :param session: The AsyncSession instance for database access.
        :return: The count of users.
        """
        query = select(func.count()).select_from(User)
        result = await session.execute(query)
        count = result.scalar()
        return count
    
    @classmethod
    async def unlock_user_account(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if user and user.is_locked:
            user.is_locked = False
            user.failed_login_attempts = 0  # Optionally reset failed login attempts
            session.add(user)
            await session.commit()
            return True
        return False
    
    @classmethod
    async def set_professional_status(cls, session: AsyncSession, user_id: UUID, status: bool, admin: User, email_service: EmailService) -> Optional[User]:
        """
        Set or unset professional status for a user and update the timestamp.
        """
        try:
            if admin.role != UserRole.ADMIN:
                raise ValueError("Only admins can set professional status")
            user = await cls.get_by_id(session, user_id)
            if not user:
                return None

            user.is_professional = bool(status)
            user.professional_status_updated_at = datetime.now(timezone.utc)
            session.add(user)
            await session.commit()
            await session.refresh(user)
            if user.is_professional:
                await email_service.send_professional_status_upgrade_email(user.email)
            return user
        except ValueError as ve:
            logger.error(f"Authorization error: {str(ve)}")
            raise
        except SQLAlchemyError as e:
            logger.error(f"Failed to set professional status for {user_id}: {e}")
            await session.rollback()
            return None
        
    @classmethod
    async def search_users(db: AsyncSession, query: str, admin: User = None):
        """
        Search users by first name, last name, or email.
        Returns a list of matching User objects.
        """
        if admin and admin.role != UserRole.ADMIN:
            raise ValueError("Only admins can search users")
        stmt = (
            select(User)
            .where(
                (User.first_name.ilike(f"%{query}%")) |
                (User.last_name.ilike(f"%{query}%")) |
                (User.email.ilike(f"%{query}%"))
            )
            .order_by(User.first_name.asc())
        )

        result = await db.execute(stmt)
        return result.scalars().all()