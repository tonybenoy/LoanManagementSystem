import datetime
import math
from app import db,ma
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import login
TYPE = {
    'customer': 0,
    'agent': 1,
    'admin': 2
}

STATE = {
    'New': 0,
    'Rejected': 1,
    'Approved': 2
}

class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    principle = db.Column(db.Float, nullable=False)
    roi = db.Column(db.Float, nullable=False)
    create_date = db.Column(db.Date, nullable=False)
    edit_date = db.Column(db.Date, nullable=False)
    tenure = db.Column(db.Integer, nullable=False)
    state = db.Column(db.Integer, nullable=False)
    user = db.Column(db.Integer,db.ForeignKey("user.id"))
    create_uid =  db.Column(db.Integer)
    edit_uid = db.Column(db.Integer)
    emi = db.Column(db.Float)
    total_amount = db.Column(db.Float)
    def __init__(self, tenure,principle, roi,user, state=STATE['New']):
        self.user = user
        self.principle = principle
        self.roi = roi
        self.state = state
        self.tenure=tenure
        self.edit_date = datetime.datetime.utcnow().date()
        self.create_date = datetime.datetime.utcnow().date()
    def emicalc(self):
        self.emi=(self.principle * (math.pow((1 + self.roi / 100), self.tenure))-self.principle)/self.tenure
        self.total_amount = self.principle * (math.pow((1 + self.roi / 100), self.tenure))
    def createuid(self,userid):
        self.create_uid=userid
    def __repr__(self):
        return '<Loan {}>'.format(self.id)

class LoanSchema(ma.ModelSchema):
    class Meta:
        model = Loan
        include_fk = True

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, nullable=False, unique=True)
    email = db.Column(db.String(120), index=True, nullable=False, unique=True)
    password_hash = db.Column(db.String(128))
    type_of_user = db.Column(db.Integer, nullable=False)
    create_date = db.Column(db.DateTime, nullable=False)
    edit_date = db.Column(db.DateTime, nullable=False)
    edit_uid =  db.Column(db.Integer, db.ForeignKey('user.id'))
    loans = db.relationship("Loan", backref="loan", lazy='dynamic')
    def __init__(self, username, email, type_of_user=TYPE['customer']):
        self.username = username
        self.email = email  
        self.type_of_user = type_of_user
        self.edit_date = datetime.datetime.utcnow().date()
        self.create_date = datetime.datetime.utcnow().date()

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return '<User {}>'.format(self.username)
    
    @login.user_loader
    def load_user(id):
        return User.query.get(int(id))
class UserSchema(ma.ModelSchema):
    class Meta:
        model = User
        include_fk = True
