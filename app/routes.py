from flask import render_template, flash, redirect,url_for,request,jsonify,make_response
from flask_login import login_user,current_user,logout_user,login_required # Login and session management 
from werkzeug.urls import url_parse
import datetime
import jwt
from functools import wraps
from app import app,login,db
from app.forms import LoginForm, ProfileForm, RegistrationForm, LoanForm, EditLoanForm, FilterForm
from app.models import User,UserSchema,Loan,LoanSchema

user_schema = UserSchema(strict=True,exclude=['password_hash'])
users_schema = UserSchema(many=True,strict=True,exclude=['password_hash'])
loan_schema = LoanSchema(strict=True)
loans_schema = LoanSchema(many=True, strict=True)

@app.route('/', methods=['GET'])
@app.route('/index', methods=['GET'])
def index():
    return render_template("index.html")

@app.route('/users',methods=['GET'])
@login_required
def users():
    if current_user.type_of_user in [1,2]:
        result = User.query.all()
        return render_template("users.html",users=result)
    else:
        flash('You are not authorised to view this!')
        return redirect(url_for('index'))

@app.route('/user/<username>',methods=['GET'])
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
@login_required
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


@app.route("/createloan",methods=['GET', 'POST'])
@login_required
def createloan():
    form = LoanForm()
    if current_user.type_of_user == 1:
        if form.validate_on_submit():
            loan = Loan(user=int(form.user.data),principle=form.principle.data, roi=form.roi.data, tenure=form.tenure.data)
            loan.createuid(current_user.id)
            loan.emicalc()
            db.session.add(loan)    
            db.session.commit()
            flash('Loan Created')
            return redirect(url_for('index'))
        return render_template('createloan.html', title='Create Loan', form=form)
    else:
        flash('You are not authorised to view this!')
        return redirect(url_for('index'))

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    form = FilterForm()
    if form.validate_on_submit():
        if current_user.type_of_user == 0:
            if form.state.data == "All":
                loans = Loan.query.filter_by(user=current_user.id,create_date=form.createdate.data,edit_date=form.updatedate.data).all()
                return render_template("loans.html", Title="Loans", user=User, loans=loans)
            else:
                loans = Loan.query.filter_by(user=current_user.id,state=int(form.state.data),create_date=form.createdate.data,edit_date=form.updatedate.data).all()
                return render_template("loans.html", Title="Loans", user=User, loans=loans)
        else:
            if form.user.data == "All" and form.state.data == "All":
                loans = Loan.query.filter_by(create_date=form.createdate.data,edit_date=form.updatedate.data).all()
                return render_template("loans.html", Title="Loans", user=User, loans=loans)
            elif form.user.data == "All":
                loans = Loan.query.filter_by(state=int(form.state.data),create_date=form.createdate.data,edit_date=form.updatedate.data).all()
                return render_template("loans.html", Title="Loans", user=User, loans=loans)
            elif form.state.data == "All":
                loans = Loan.query.filter_by(user=int(form.user.data),create_date=form.createdate.data,edit_date=form.updatedate.data).all()
                return render_template("loans.html", Title="Loans", user=User, loans=loans)
            else:
                return render_template('search.html', title='Search', form=form)
    else:
        return render_template('search.html', title='Search', form=form)


@app.route("/loans",methods=['GET','POST'])
@login_required
def loans():
    if current_user.type_of_user in [1, 2]:
        loans = Loan.query.all()
    else:
        loans = Loan.query.filter_by(user=current_user.id).all()
    return render_template("loans.html",Title="Loans",user=User,loans=loans)

@app.route('/editprofile/<username>', methods=['GET', 'POST'])
@login_required
def edit_profile(username):
    form = ProfileForm()
    if form.validate_on_submit():
        if current_user.type_of_user in [1, 2] or username == current_user.username:
            user = User.query.filter_by(username=username).first_or_404()
            user.username = form.username.data
            user.email = form.email.data
            user.edit_date = datetime.datetime.utcnow().date()
            if current_user.type_of_user in [2]:
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


@app.route('/editloan/<loanid>', methods=['GET', 'POST'])
@login_required
def editloan(loanid):
    form = EditLoanForm()
    if request.method == 'POST':
        if current_user.type_of_user != 0:
            loan = Loan.query.filter_by(id=loanid).first_or_404()
            if form.approve.data == True and current_user.type_of_user == 2:
                loan.state = 2
                db.session.commit()
                return redirect(url_for('editloan',loanid=loan.id))
            elif form.reject.data == True and current_user.type_of_user == 2:
                loan.state = 1
                db.session.commit()
                return redirect(url_for('editloan',loanid=loan.id))
            elif form.submit.data == True and current_user.type_of_user == 1:
                loan.roi = form.roi.data
                loan.tenure = form.tenure.data
                loan.principle = form.principle.data
                loan.edit_date = datetime.datetime.utcnow().date()
                loan.edit_uid = current_user.id
                db.session.commit()
                flash('Your changes have been saved.')
                return redirect(url_for('editloan',loanid=loan.id))
            else:
                flash('Incorrect output.')
                return redirect(url_for('index'))
        else:
            flash("Unauthorised Request")
            return redirect(url_for("index"))
    elif request.method == 'GET':
        STATE = {   0:'New',
                    1: 'Rejected',
                    2:'Approved' }
        loan = Loan.query.filter_by(id=loanid).first_or_404()
        form.tenure.data = loan.tenure
        form.principle.data = loan.principle
        form.roi.data = loan.roi
        state = STATE[loan.state]
        return render_template('edit_loan.html', title='Edit Loan', form=form, state=state)

@app.route('/' + app.config["API_FOR"] + '/' + app.config["API_VERSION"] + "/user", methods=['POST'])
def api_create_user():
    data = request.get_json()
    user = User(username=data["username"], email=data["email"])
    user.set_password(data["password"])
    db.session.add(user)    
    db.session.commit()
    return jsonify({"message": "User "+data["username"]+" created"})

def token_required(func):
    @wraps(func)
    def decorated_func(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers["x-access-token"]
        if not token:
            return jsonify({"Message": "Token not found"}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(username=data["username"]).first()
        except:
            return jsonify({"Message": "Token Invalid"}), 401
        return func(current_user,*args,**kwargs)
    return decorated_func

@app.route('/' + app.config["API_FOR"] + '/' + app.config["API_VERSION"] + "/login",methods=['GET'])
def api_login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response("COund not verify",401,{'WWW-Authenticate':'Basic realm="Login required"'})
    user = User.query.filter_by(username=auth.username).first()
    if not user:
        return make_response("COund not verify",401,{'WWW-Authenticate':'Basic realm="Login required"'})
    if user.check_password(auth.password):
        token = jwt.encode({'username': auth.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({"token": token.decode('UTF-8')})
    return make_response("COund not verify",401,{'WWW-Authenticate':'Basic realm="Login required"'})

@app.route('/' + app.config["API_FOR"] + '/' + app.config["API_VERSION"] + "/users",methods=['GET'])
@token_required
def api_users(current_user):
    if current_user.type_of_user == 0:
        return jsonify({"Message": "Unauthorized"}), 403
    else:
        users = User.query.all()
        result = users_schema.dump(users)
        return jsonify(result.data)
        

@app.route('/' + app.config["API_FOR"] + '/' + app.config["API_VERSION"] + "/loans",methods=['GET'])
@token_required
def api_loans(current_user):
    if current_user.type_of_user == 0:
        loans = Loan.query.filter_by(user=current_user.id)
    else:
        loans = Loan.query.all()
    result = loans_schema.dump(loans)
    return jsonify(result.data)

@app.route('/' + app.config["API_FOR"] + '/' + app.config["API_VERSION"] + "/loan/<id>",methods=['GET'])
@token_required
def api_loan(current_user, id):
    print(request.headers)
    loan = Loan.query.filter_by(id=id).first()
    if current_user.type_of_user == 0 and loan.user == current_user.id:
        result = loan_schema.dump(loan).data
    elif current_user.type_of_user in [2,1]:
        result = loan_schema.dump(loan).data
    else:
        result = {"Message": "Unauthorized"}
    return jsonify(result)

@app.route('/' + app.config["API_FOR"] + '/' + app.config["API_VERSION"] + "/user/<username>",methods=['GET'])
@token_required
def api_user(current_user,username):
    user = User.query.filter_by(username=username).first()
    if current_user.type_of_user == 0 and user.username == current_user.username:
        result = user_schema.dump(user).data
    elif current_user.type_of_user in [2,1]:
        result = user_schema.dump(user).data
    else:
        result = {"Message": "Unauthorized"}
    return jsonify(result)