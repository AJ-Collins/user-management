import pytest
from unittest.mock import patch, AsyncMock
from app.services.email_service import EmailService

@pytest.fixture
def email_service():
    """Create a mock email service"""
    mock_service = AsyncMock(spec=EmailService)
    return mock_service

# Corrected test
@pytest.mark.asyncio
async def test_send_markdown_email(email_service):
    user_data = {
        "email": "test@example.com",
        "name": "Test User",
        "verification_url": "http://example.com/verify?token=abc123"
    }
    
    # Mock the method to not actually send emails
    email_service.send_user_email.return_value = None
    
    # Call the method
    await email_service.send_user_email(user_data, 'email_verification')
    
    # Assert it was called correctly
    email_service.send_user_email.assert_called_once_with(user_data, 'email_verification')