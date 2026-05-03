"""
Shared pytest fixtures.
"""
import os
import pytest

# Use a test database URL so tests don't touch production
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/1")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-unit-tests-only")
os.environ.setdefault("APP_ENV", "test")
