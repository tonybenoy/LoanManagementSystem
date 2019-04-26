from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_marshmallow import Marshmallow
from flask_moment import Moment

from config import Config #Import configuration from config.py.
app = Flask(__name__) #creating the app object
app.config.from_object(Config)  #Applying config to app
login = LoginManager(app) #LoginManager is user to manage user sessions
login.login_view = 'login' # For login object 
db = SQLAlchemy(app) # ORM obect for database
ma = Marshmallow(app)
migrate = Migrate(app, db)  # Migrate for alembic support 
moment = Moment(app)
from app import routes,models #Importing all routes and models from routes.py