from flask_wtf import FlaskForm
from wtforms import SelectField, BooleanField, SubmitField, IntegerField, PasswordField, RadioField, StringField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length
from app.models import User
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[
                             DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')
class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    type_of_user = RadioField("User Type",choices=[("2","Admin"),("0","Customer"),("1","Agent")])
    submit = SubmitField('Update')

class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    passwordrep = PasswordField('Repeat Password', validators=[
                                DataRequired(), EqualTo('password')])
    submit = SubmitField("Register")

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')