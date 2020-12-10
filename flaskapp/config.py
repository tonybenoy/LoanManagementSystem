import os


class Config(object):  # Add all app related config in here
    SECRET_KEY = os.environ.get("SECRET_KEY") or "APPPASSWORD"
    SQLALCHEMY_DATABASE_URI = (
        "postgresql+psycopg2://postgres:postgres@postgres:5432/loanmanagement"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    API_VERSION = "0.0.1"
    API_FOR = "loanmanagement"


class TestConfig(object):
    DEBUG = True
    SECRET_KEY = os.environ.get("SECRET_KEY") or "APPPASSWORD"
    SQLALCHEMY_DATABASE_URI = (
        "postgresql+psycopg2://postgres:postgres@localhost:5432/loanmanagementtest"
    )
    # Incase you need to through compose
    # SQLALCHEMY_DATABASE_URI = (
    #     "postgresql+psycopg2://postgres:postgres@postgres:5432/loanmanagementtest"
    # )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    API_VERSION = "0.0.1"
    API_FOR = "loanmanagement"
