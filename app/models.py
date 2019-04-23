import datetime
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import login
TYPE = {
    'customer': 0,
    'agent': 1,
    'admin': 2
}
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, nullable=False, unique=True)
    email = db.Column(db.String(120), index=True, nullable=False, unique=True)
    password_hash = db.Column(db.String(128))
    type_of_user = db.Column(db.Integer, nullable=False)
    create_date = db.Column(db.DateTime, nullable=False)
    edit_date = db.Column(db.DateTime, nullable=False)
    edit_uid = db.Column(db.Integer)
    def __init__(self, username, email, type_of_user=TYPE['customer']):
        self.username = username
        self.email = email
        self.type_of_user = type_of_user
        self.edit_date = datetime.datetime.utcnow()
        self.create_date = datetime.datetime.utcnow()

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return '<User {}>'.format(self.username)
    
    @login.user_loader
    def load_user(id):
        return User.query.get(int(id))