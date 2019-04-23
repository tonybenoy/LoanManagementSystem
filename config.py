import os
class Config(object): #Add all app related config in here
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'APPPASSWORD'
    SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://tony:tony@localhost/loanmanagement'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    API_VERSION = "0.0.1"
    API_FOR = "loanmanagement"