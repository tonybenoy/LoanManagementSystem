from flask_wtf import FlaskForm
import datetime
from flask_login import current_user
from wtforms import (
    SelectField,
    FloatField,
    BooleanField,
    SubmitField,
    IntegerField,
    PasswordField,
    RadioField,
    StringField,
    DateField,
)
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length
from app.models import User


class LoginForm(FlaskForm):  # wtf form
    username = StringField("Username", validators=[DataRequired()])  # form fields
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Remember Me")
    submit = SubmitField("Sign In")


class ProfileForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    type_of_user = RadioField(
        "User Type", choices=[("2", "Admin"), ("0", "Customer"), ("1", "Agent")]
    )
    submit = SubmitField("Update")


class LoanForm(FlaskForm):
    user = SelectField("Customer", validators=[DataRequired()])
    principle = FloatField("Principle", validators=[DataRequired()])
    roi = FloatField("Rate Of interest", validators=[DataRequired()])
    tenure = IntegerField("Tenure(In Months)", validators=[DataRequired()])
    submit = SubmitField("Create")

    def __init__(self):  # Dynamic choices for select field
        super(LoanForm, self).__init__()
        users = []
        for user in User.query.filter_by(type_of_user=0).all():
            users.append((str(user.id), user.username))
        self.user.choices = users


class FilterForm(FlaskForm):
    user = SelectField("Customer")
    createdate = DateField(
        "Date Created", default=datetime.datetime.utcnow(), format="%Y-%m-%d"
    )
    updatedate = DateField(
        "Date updated", default=datetime.datetime.utcnow(), format="%Y-%m-%d"
    )
    state = SelectField(
        "State",
        choices=[("1", "Accepted"), ("0", "New"), ("2", "Rejected"), ("All", "All")],
    )
    submit = SubmitField("Search")

    def __init__(self):
        super(FilterForm, self).__init__()
        if current_user.type_of_user == 0:
            users = [(str(current_user.id), current_user.username)]
        else:
            users = [("All", "All")]
            for user in User.query.filter_by(type_of_user=0).all():
                users.append((str(user.id), user.username))
        self.user.choices = users


class EditLoanForm(FlaskForm):
    principle = FloatField("Principle", validators=[DataRequired()])
    roi = FloatField("Rate Of interest", validators=[DataRequired()])
    tenure = IntegerField("Tenure(In Months)", validators=[DataRequired()])
    submit = SubmitField("Update")
    approve = SubmitField("Approve")
    rollback = SubmitField("RollBack")
    reject = SubmitField("Reject")


class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    passwordrep = PasswordField(
        "Repeat Password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Register")

    def validate_username(self, username):  # username already used
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError("Please use a different username.")

    def validate_email(self, email):  # Email already used
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError("Please use a different email address.")
