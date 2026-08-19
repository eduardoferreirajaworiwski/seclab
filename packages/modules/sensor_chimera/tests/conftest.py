import os

os.environ.setdefault("SECLAB_DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECLAB_API_KEY_PEPPER", "test-pepper-not-for-prod")
