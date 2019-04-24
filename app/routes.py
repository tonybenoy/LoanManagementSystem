from flask import render_template, flash, redirect,url_for,request,jsonify
from flask_login import login_user,current_user,logout_user,login_required # Login and session management 
from werkzeug.urls import url_parse
import datetime
from app import app,login,db
from app.forms import LoginForm, ProfileForm, RegistrationForm
from app.models import User,UserSchema

user_schema = UserSchema()
users_schema = UserSchema(many=True)

@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def index():
    return render_template("index.html")

@app.route('/users',methods=['GET','POST'])
@login_required
def users():
    if current_user.type_of_user in [1,2]:
        result = User.query.all()
        return render_template("users.html",users=result)
    else:
        flash('You are not authorised to view this!')
        return redirect(url_for('index'))

@app.route('/user/<username>',methods=['GET','POST'])
@login_required
def user(username):
    if current_user.type_of_user in [1,2] or username == current_user.username:
        user = User.query.filter_by(username=username).first_or_404()
        return render_template("user.html",user=user)
    else:
        flash('You are not authorised to view this!')
        return redirect(url_for('index'))

@app.route('/login',methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/edit_profile/<username>', methods=['GET', 'POST'])
@login_required
def edit_profile(username):
    form = ProfileForm()
    if form.validate_on_submit():
        if current_user.type_of_user in [1, 2] or username == current_user.username:
            user = User.query.filter_by(username=username).first_or_404()
            user.username = form.username.data
            user.email = form.email.data
            user.edit_date = datetime.datetime.utcnow()
            user.type_of_user = int(form.type_of_user.data)
            user.edit_uid = current_user.id
            db.session.commit()
            flash('Your changes have been saved.')
            return redirect(url_for('edit_profile',username=user.username))
        else:
            flash('You are not authorised to view this!')
            return redirect(url_for('index'))
    elif request.method == 'GET':
        if current_user.type_of_user in [1,2] or username == current_user.username:
            user = User.query.filter_by(username=username).first_or_404()
            form.username.data = user.username
            form.email.data = user.email
            form.type_of_user.data = str(user.type_of_user)
            return render_template('edit_profile.html', title='Edit Profile',form=form)
        else:
            flash('You are not authorised to view this!')
            return redirect(url_for('index'))

