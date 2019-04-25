from flask_wtf import FlaskForm
from wtforms import SelectField, FloatField,BooleanField, SubmitField, IntegerField, PasswordField, RadioField, StringField,DateField
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

class LoanForm(FlaskForm):
    user = SelectField("Customer", validators=[DataRequired()])
    principle = FloatField('Principle', validators=[DataRequired()])
    roi = FloatField('Rate Of interest', validators=[DataRequired()])
    tenure = IntegerField("Tenure(In Months)", validators=[DataRequired()])
    submit = SubmitField('Create')
    def __init__(self):
        super(LoanForm, self).__init__()
        users =[]
        for user in User.query.filter_by(type_of_user=0).all():
            users.append((str(user.id),user.username))
        self.user.choices = users

class FilterForm(FlaskForm):
    user = SelectField("Customer")
    createdate = DateField("Date Created")
    updatedate = DateField("Date updated")
    state = SelectField("State",choices=[("1","Accepted"),("0","New"),("2","Rejected"),("All","All")])
    submit = SubmitField("Search")
class EditLoanForm(FlaskForm):
    principle = FloatField('Principle', validators=[DataRequired()])
    roi = FloatField('Rate Of interest', validators=[DataRequired()])
    tenure = IntegerField("Tenure(In Months)", validators=[DataRequired()])
    submit = SubmitField('Update')
    approve = SubmitField('Approve')
    reject = SubmitField('Reject')

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