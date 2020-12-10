from flask import (
    render_template,
    flash,
    redirect,
    url_for,
    request,
    jsonify,
    make_response,
)
from flask_login import (
    login_user,
    current_user,
    logout_user,
    login_required,
)  # Login and session management
from werkzeug.urls import url_parse  # To get the next url
import datetime
import jwt  # For jwt
from functools import wraps  # To define decorators
from dateutil import tz  # Fore timezone management
from app import app, login, db  # app specific stuff
from app.forms import (
    LoginForm,
    ProfileForm,
    RegistrationForm,
    LoanForm,
    EditLoanForm,
    FilterForm,
)  # Flask-wtf forms
from app.models import (
    User,
    UserSchema,
    Loan,
    LoanSchema,
    LoanRollback,
)  # SQLAlchemy models

user_schema = UserSchema(strict=True, exclude=["password_hash"])  # Marshmallow Schema
users_schema = UserSchema(
    many=True, strict=True, exclude=["password_hash"]
)  # Marshmallow Schema for multiple
loan_schema = LoanSchema(strict=True)  # Marshmallow Schema
loans_schema = LoanSchema(many=True, strict=True)  # Marshmallow Schema for multiple


@app.route("/", methods=["GET"])  # defining rotes and http methods
@app.route("/index", methods=["GET"])
def index():
    """Endpoint for home"""
    return render_template(
        "index.html"
    )  # render html template (Contains jinja templating)


@app.route("/users", methods=["GET"])
@login_required
def users():
    """Endpoint to get all users"""
    if current_user.type_of_user in [
        1,
        2,
    ]:  # Make sure use in specific user group can be better implemented
        result = User.query.all()
        return render_template(
            "users.html", users=result
        )  # Passing values(all users) to be used by jinja templating engine
    else:
        flash("You are not authorised to view this!")  # Flashing messages
        return redirect(url_for("index"))


@app.route("/user/<username>", methods=["GET"])  # Getting parameters in the url
@login_required  # login required to access the specific route
def user(username):  # Getting parameters in the url into a variable
    """Endpoint to get information of a specific user"""
    if (
        current_user.type_of_user in [1, 2] or username == current_user.username
    ):  # Checks on the user type
        user = User.query.filter_by(username=username).first_or_404()
        return render_template("user.html", user=user)
    else:
        flash("You are not authorised to view this!")
        return redirect(url_for("index"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Endpoint to  log the user in"""
    if current_user.is_authenticated:  # used to check the user is already logged in
        return redirect(url_for("index"))
    form = LoginForm()  # Creating a form instance
    if (
        form.validate_on_submit() or request.method == "POST"
    ):  # Checking if a post request or if the button is submitted
        user = User.query.filter_by(
            username=form.username.data
        ).first()  # Getting the user with specific filters
        if user is None or not user.check_password(
            form.password.data
        ):  # Authenticating the user
            flash("Invalid username or password")
            return redirect(url_for("login"))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get("next")
        if (
            not next_page or url_parse(next_page).netloc != ""
        ):  # Passing on the the page wherethe user is supposed to be redirected after logging in
            next_page = url_for("index")
        return redirect(next_page)
    return render_template(
        "login.html", title="Sign In", form=form
    )  # passing the form to jinja template


@app.route("/logout")
@login_required
def logout():
    """TO logout the user"""
    logout_user()  # Logout the user
    return redirect(url_for("index"))
    if current_user.is_authenticated:
        return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Endpoint to register/add more users to the system"""
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = RegistrationForm()
    if form.validate_on_submit() or request.method == "POST":
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)  # add user to db
        db.session.commit()  # commit user to db
        flash("Congratulations, you are now a registered user!")
        return redirect(url_for("login"))
    return render_template("register.html", title="Register", form=form)


@app.route("/createloan", methods=["GET", "POST"])
@login_required
def createloan():
    """Endpoint to create loans"""
    form = LoanForm()
    if current_user.type_of_user == 1:
        if form.validate_on_submit():
            loan = Loan(
                user=int(form.user.data),
                principle=form.principle.data,
                roi=form.roi.data,
                tenure=form.tenure.data,
            )
            loan.createuid(current_user.id)
            loan.emicalc()
            db.session.add(loan)
            db.session.commit()
            flash("Loan Created")
            return redirect(url_for("index"))
        return render_template("createloan.html", title="Create Loan", form=form)
    else:
        flash("You are not authorised to view this!")
        return redirect(url_for("index"))


@app.route("/search", methods=["GET", "POST"])
@login_required
def search():  # Not a very good  implementation
    """Endpoint to filter out loan results"""
    form = FilterForm()
    if form.validate_on_submit():
        if current_user.type_of_user == 0:
            if form.state.data == "All":
                loans = Loan.query.filter_by(
                    user=current_user.id,
                    create_date=form.createdate.data,
                    edit_date=form.updatedate.data,
                ).all()
                return render_template(
                    "loans.html", Title="Loans", user=User, loans=loans
                )
            else:
                loans = Loan.query.filter_by(
                    user=current_user.id,
                    state=int(form.state.data),
                    create_date=form.createdate.data,
                    edit_date=form.updatedate.data,
                ).all()
                return render_template(
                    "loans.html", Title="Loans", user=User, loans=loans
                )
        else:
            if form.user.data == "All" and form.state.data == "All":
                loans = Loan.query.filter_by(
                    create_date=form.createdate.data, edit_date=form.updatedate.data
                ).all()
                return render_template(
                    "loans.html", Title="Loans", user=User, loans=loans
                )
            elif form.user.data == "All":
                loans = Loan.query.filter_by(
                    state=int(form.state.data),
                    create_date=form.createdate.data,
                    edit_date=form.updatedate.data,
                ).all()
                return render_template(
                    "loans.html", Title="Loans", user=User, loans=loans
                )
            elif form.state.data == "All":
                loans = Loan.query.filter_by(
                    user=int(form.user.data),
                    create_date=form.createdate.data,
                    edit_date=form.updatedate.data,
                ).all()
                return render_template(
                    "loans.html", Title="Loans", user=User, loans=loans
                )
            else:
                return render_template("search.html", title="Search", form=form)
    else:
        return render_template("search.html", title="Search", form=form)


@app.route("/loans", methods=["GET", "POST"])
@login_required
def loans():
    """Endpoint to get all loans. No filtering except usertype"""
    if current_user.type_of_user in [1, 2]:
        loans = Loan.query.all()
    else:
        loans = Loan.query.filter_by(user=current_user.id).all()
    return render_template("loans.html", Title="Loans", user=User, loans=loans)


@app.route("/editprofile/<username>", methods=["GET", "POST"])
@login_required
def edit_profile(username):
    """Endpoint to edit a user profile."""
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
            flash("Your changes have been saved.")
            return redirect(url_for("edit_profile", username=user.username))
        else:
            flash("You are not authorised to view this!")
            return redirect(url_for("index"))
    elif request.method == "GET":
        if current_user.type_of_user in [1, 2] or username == current_user.username:
            user = User.query.filter_by(username=username).first_or_404()
            form.username.data = user.username
            form.email.data = user.email
            form.type_of_user.data = str(user.type_of_user)
            return render_template("edit_profile.html", title="Edit Profile", form=form)
        else:
            flash("You are not authorised to view this!")
            return redirect(url_for("index"))


@app.route("/editloan/<loanid>", methods=["GET", "POST"])
@login_required
def editloan(loanid):
    """Endpoint to edit loans. Needs loan id"""
    form = EditLoanForm()
    if request.method == "POST":
        if current_user.type_of_user != 0:
            loanold = LoanRollback.query.filter_by(loan=id).first()
            if not loanold:
                loanold = LoanRollback(
                    parent=loan.id,
                    tenure=loan.tenure,
                    principle=loan.principle,
                    roi=loan.roi,
                )
                db.session.add(loanold)
            loan = Loan.query.filter_by(id=loanid).first_or_404()
            if (
                form.approve.data == True and current_user.type_of_user == 2
            ):  # perform action based on button pressed
                loan.state = 2
                db.session.commit()
                flash("Loan approved!")
                return redirect(url_for("editloan", loanid=loan.id))
            elif form.reject.data == True and current_user.type_of_user == 2:
                loan.state = 1
                db.session.commit()
                flash("Loan rejected!")
                return redirect(url_for("editloan", loanid=loan.id))
            if form.rollback.data == True and current_user.type_of_user == 1:
                loan.roi, loanold.roi = loanold.roi, loan.roi
                loan.principle, loanold.principle = loanold.principle, loan.principle
                loan.tenure, loanold.tenure = loanold.tenure, loan.tenure
                db.session.commit()
                flash("Loan rolled back to previos version!")
                return redirect(url_for("editloan", loanid=loan.id))
            elif form.submit.data == True and current_user.type_of_user == 1:
                loanold.roi = loan.roi
                loanold.tenure = loan.tenure
                loanold.principle = loan.principle
                loan.roi = form.roi.data
                loan.tenure = form.tenure.data
                loan.principle = form.principle.data
                loan.edit_date = datetime.datetime.utcnow().date()
                loan.edit_uid = current_user.id
                db.session.commit()
                flash("Your changes have been saved.")
                return redirect(url_for("editloan", loanid=loan.id))
            else:
                flash("Incorrect output.")
                return redirect(url_for("index"))
        else:
            flash("Unauthorised Request")
            return redirect(url_for("index"))
    elif request.method == "GET":
        STATE = {0: "New", 1: "Rejected", 2: "Approved"}
        loan = Loan.query.filter_by(id=loanid).first_or_404()
        form.tenure.data = loan.tenure
        form.principle.data = loan.principle
        form.roi.data = loan.roi
        state = STATE[loan.state]
        return render_template(
            "edit_loan.html", title="Edit Loan", form=form, state=state
        )


@app.route(
    "/" + app.config["API_FOR"] + "/" + app.config["API_VERSION"] + "/user",
    methods=["POST"],
)  # api end point to create user
def api_create_user():
    """API endpoint to create new users for the system"""
    data = request.get_json()
    if data == None:
        return jsonify({"message": "No data received"})
    if "username" not in data.keys():
        return jsonify({"message": "No username specified"})
    if "password" not in data.keys():
        return jsonify({"message": "No password specified"})
    if "email" not in data.keys():  # Regex must be added to check if valid email
        return jsonify({"message": "No email specified"})
    user = User(username=data["username"], email=data["email"])
    user.set_password(data["password"])
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User " + data["username"] + " created"})


def token_required(func):
    """Decorater for checking if supplied token is valid and assign the user
    to current user
    """

    @wraps(func)
    def decorated_func(*args, **kwargs):
        token = None
        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]
        if not token:
            return jsonify({"Message": "Token not found"}), 401
        try:
            data = jwt.decode(
                token, app.config["SECRET_KEY"]
            )  # Decoding the jwt token to verify the user
            current_user = User.query.filter_by(username=data["username"]).first()
        except:
            return jsonify({"Message": "Token Invalid"}), 401
        return func(current_user, *args, **kwargs)

    return decorated_func


@app.route(
    "/" + app.config["API_FOR"] + "/" + app.config["API_VERSION"] + "/login",
    methods=["GET"],
)
def api_login():
    """API endpoint for user to login with username and password and get JWT for further authentication"""
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response(
            "COund not verify",
            401,
            {"WWW-Authenticate": 'Basic realm="Login required"'},
        )
    user = User.query.filter_by(username=auth.username).first()
    if not user:
        return make_response(
            "COund not verify",
            401,
            {"WWW-Authenticate": 'Basic realm="Login required"'},
        )
    if user.check_password(auth.password):
        token = jwt.encode(
            {
                "username": auth.username,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
            },
            app.config["SECRET_KEY"],
        )  # Generate token use keypairs or a better algorith rather than using a secret key
        return jsonify({"token": token.decode("UTF-8")})
    return make_response(
        "COund not verify", 401, {"WWW-Authenticate": 'Basic realm="Login required"'}
    )


@app.route(
    "/" + app.config["API_FOR"] + "/" + app.config["API_VERSION"] + "/users",
    methods=["GET"],
)
@token_required
def api_users(current_user):
    """API endpint to get all users. Not accessible to customers"""
    if current_user.type_of_user == 0:
        return jsonify({"Message": "Unauthorized"}), 403
    else:
        users = User.query.all()
        result = users_schema.dump(users)  # serializing using marshmallow schema
        return jsonify(result.data)


@app.route(
    "/" + app.config["API_FOR"] + "/" + app.config["API_VERSION"] + "/loans",
    methods=["GET"],
)
@token_required
def api_loans(current_user):
    """API end point to get loans. Accessble to everyone but the reponse/data availability depends on the user type.
    Parameters for filtering supported are username,create_date,edit_date and state.
    """
    from_zone = tz.gettz("UTC")
    to_zone = (
        tz.gettz(request.headers["timezone"])
        if "timezone" in request.headers
        else tz.gettz("India/Delhi")
    )  # getting the timezone
    if not (
        request.args.get("username")
        and request.args.get("create_date")
        and request.args.get("edit_date")
        and request.args.get("state")
    ):
        if current_user.type_of_user == 0:
            loans = Loan.query.filter_by(user=current_user.id)
        else:
            loans = Loan.query.all()
        result = loans_schema.dump(loans)
        for item in result.data:
            item["create_date"] = (
                datetime.datetime.strptime(item["create_date"][0:10], "%Y-%m-%d")
                .replace(tzinfo=from_zone)
                .astimezone(to_zone)
            )  # Converting time to the timezone
            item["edit_date"] = (
                datetime.datetime.strptime(item["edit_date"][0:10], "%Y-%m-%d")
                .replace(tzinfo=from_zone)
                .astimezone(to_zone)
            )
    else:
        loans = Loan.query
        if request.args.get("username"):
            loan.filter_by(user=request.args.get("username"))
        if request.args.get("create_date"):
            loans.filter_by(create_date=request.args.get("create_date"))
        if request.args.get("edit_date"):
            loans.filter_by(edit_date=request.args.get("edit_date"))
        if request.args.get("state"):
            loans.filter_by(state=request.args.get("state"))
        result = loans_schema.dump(loans.all())
        for item in result.data:
            item["create_date"] = (
                datetime.datetime.strptime(item["create_date"][0:10], "%Y-%m-%d")
                .replace(tzinfo=from_zone)
                .astimezone(to_zone)
            )
            item["edit_date"] = (
                datetime.datetime.strptime(item["edit_date"][0:10], "%Y-%m-%d")
                .replace(tzinfo=from_zone)
                .astimezone(to_zone)
            )
    return jsonify(result.data)


@app.route(
    "/" + app.config["API_FOR"] + "/" + app.config["API_VERSION"] + "/loan/<id>",
    methods=["GET"],
)
@token_required
def api_loan(current_user, id):
    """API end point for getting a specific loan. Needs the id of the loan to be specified."""
    from_zone = tz.gettz("UTC")
    to_zone = (
        tz.gettz(request.headers["timezone"])
        if "timezone" in request.headers
        else tz.gettz("India/Delhi")
    )
    loan = Loan.query.filter_by(id=id).first()
    if current_user.type_of_user == 0 and loan.user == current_user.id:
        result = loan_schema.dump(loan).data
        result["create_date"] = (
            datetime.datetime.strptime(result["create_date"][0:10], "%Y-%m-%d")
            .replace(tzinfo=from_zone)
            .astimezone(to_zone)
        )
        result["edit_date"] = (
            datetime.datetime.strptime(result["edit_date"][0:10], "%Y-%m-%d")
            .replace(tzinfo=from_zone)
            .astimezone(to_zone)
        )
    elif current_user.type_of_user in [2, 1]:
        result = loan_schema.dump(loan).data
        result["create_date"] = (
            datetime.datetime.strptime(result["create_date"][0:10], "%Y-%m-%d")
            .replace(tzinfo=from_zone)
            .astimezone(to_zone)
        )
        result["edit_date"] = (
            datetime.datetime.strptime(result["edit_date"][0:10], "%Y-%m-%d")
            .replace(tzinfo=from_zone)
            .astimezone(to_zone)
        )
    else:
        result = {"Message": "Unauthorized"}
    return jsonify(result)


@app.route(
    "/" + app.config["API_FOR"] + "/" + app.config["API_VERSION"] + "/user/<username>",
    methods=["GET"],
)
@token_required
def api_user(current_user, username):
    """API endpoint to get specific information about a certain username"""
    from_zone = tz.gettz("UTC")
    to_zone = (
        tz.gettz(request.headers["timezone"])
        if "timezone" in request.headers
        else tz.gettz("India/Delhi")
    )
    user = User.query.filter_by(username=username).first()
    if current_user.type_of_user == 0 and user.username == current_user.username:
        result = user_schema.dump(user).data
        result["create_date"] = (
            datetime.datetime.strptime(result["create_date"][0:10], "%Y-%m-%d")
            .replace(tzinfo=from_zone)
            .astimezone(to_zone)
        )
        result["edit_date"] = (
            datetime.datetime.strptime(result["edit_date"][0:10], "%Y-%m-%d")
            .replace(tzinfo=from_zone)
            .astimezone(to_zone)
        )
    elif current_user.type_of_user in [2, 1]:
        result = user_schema.dump(user).data
        result["create_date"] = (
            datetime.datetime.strptime(result["create_date"][0:10], "%Y-%m-%d")
            .replace(tzinfo=from_zone)
            .astimezone(to_zone)
        )
        result["edit_date"] = (
            datetime.datetime.strptime(result["edit_date"][0:10], "%Y-%m-%d")
            .replace(tzinfo=from_zone)
            .astimezone(to_zone)
        )
    else:
        result = {"Message": "Unauthorized"}
    return jsonify(result)


@app.route(
    "/" + app.config["API_FOR"] + "/" + app.config["API_VERSION"] + "/createloan",
    methods=["POST"],
)
@token_required
def api_create_loan(current_user):
    """API endpoint to create new loans. Only accessible by users of type agent"""
    if current_user.type_of_user != 1:
        return jsonify({"Message": "Unauthorized"})
    else:
        data = request.get_json()
        if not data:
            return jsonify({"message": "No data"})
        if "userid" not in data.keys():
            return jsonify({"message": "userid not found"})
        if "principle" not in data.keys():
            return jsonify({"message": "principle not found"})
        if "roi" not in data.keys():
            return jsonify({"message": "roi not found"})
        if "tenure" not in data.keys():
            return jsonify({"message": "tenure not found"})
        loan = Loan(
            user=int(data["userid"]),
            principle=data["principle"],
            roi=data["roi"],
            tenure=data["tenure"],
        )
        loan.emicalc()
        loan.create_uid = current_user.id
        db.session.add(loan)
        db.session.commit()
        return jsonify({"message": "Loan created"})


@app.route(
    "/" + app.config["API_FOR"] + "/" + app.config["API_VERSION"] + "/approve/<id>",
    methods=["POST"],
)
@token_required
def api_approve_loan(current_user, id):
    """API endpoint to accept a loan. Only works if user is of type admin"""
    if current_user.type_of_user != 2:
        return jsonify({"Message": "Unauthorized"})
    else:
        loan = Loan.query.filter_by(id=id).first()
        if loan:
            loan.state = 2
            db.session.commit()
            return jsonify({"message": "Loan approved"})
        else:
            return jsonify({"message": "Loan not found"})


@app.route(
    "/" + app.config["API_FOR"] + "/" + app.config["API_VERSION"] + "/reject/<id>",
    methods=["POST"],
)
@token_required
def api_reject_loan(current_user, id):
    """API endpoint to reject loans. Only works if user is of type admin"""
    if current_user.type_of_user != 2:
        return jsonify({"Message": "Unauthorized"})
    else:
        loan = Loan.query.filter_by(id=id).first()
        if loan:
            loan.state = 1
            db.session.commit()
            return jsonify({"message": "Loan rejected"})
        else:
            return jsonify({"message": "Loan not found"})


@app.route(
    "/" + app.config["API_FOR"] + "/" + app.config["API_VERSION"] + "/rollback/<id>",
    methods=["POST"],
)
@token_required
def api_rollback_loan(current_user, id):
    """API endpoint to rollback loans. Only works if user is of type agent"""
    if current_user.type_of_user != 1:
        return jsonify({"Message": "Unauthorized"})
    else:
        loan = Loan.query.filter_by(id=id).first()
        loanold = LoanRollback.query.filter_by(loan=id).first()
        if not loanold:
            return jsonify({"Message": "No Previos available"})
        if loan:
            loan.roi, loanold.roi = loanold.roi, loan.roi
            loan.principle, loanold.principle = loanold.principle, loan.principle
            loan.tenure, loanold.tenure = loanold.tenure, loan.tenure
            db.session.commit()
            return jsonify({"message": "Loan Rollbacked to prev version"})
        else:
            return jsonify({"message": "Loan not found"})


@app.route(
    "/" + app.config["API_FOR"] + "/" + app.config["API_VERSION"] + "/user/<username>",
    methods=["PUT"],
)
@token_required
def api_user_edit(current_user, username):
    """API endpoint to edit a user"""
    data = request.get_json()
    edit = False
    user = User.query.filter_by(username=username).first()
    if user:
        if (
            current_user.username == username or current_user.type_of_user in [1, 2]
        ) and data["email"]:
            user.email = data["email"]
            edit = True
        if current_user.type_of_user == 2 and data["type_of_user"]:
            user.type_of_user = data["type_of_user"]
            edit = True
        if edit:
            user.edit_date = datetime.datetime.utcnow().date()
            user.edit_uid = current_user.id
            db.session.commit()
            return jsonify({"message": "User Edited"})
        else:
            return jsonify({"message": "User Not edited"})
    else:
        return jsonify({"message": "User Not found"})


@app.route(
    "/" + app.config["API_FOR"] + "/" + app.config["API_VERSION"] + "/loan/<id>",
    methods=["PUT"],
)
@token_required
def api_loan_edit(current_user, id):
    """API endpoint to edit loans."""
    if current_user.type_of_user in [0, 2]:
        return jsonify({"message": "Unauthorized"})
    data = request.get_json()
    edit = False
    loan = Loan.query.filter_by(id=id).first()
    loanold = LoanRollback.query.filter_by(loan=id).first()
    if loan:
        if loan.state != 0:
            return jsonify({"message": "Loan not in editable state"})
        else:
            if not loanold:
                loanold = LoanRollback(
                    parent=loan.id,
                    tenure=loan.tenure,
                    principle=loan.principle,
                    roi=loan.roi,
                )
                db.session.add(loanold)
                db.session.commit()
            if data["roi"]:
                loanold.roi = loan.roi
                loan.roi = data["roi"]
                edit = True
            if data["principle"]:
                loanold.principle = loan.principle
                loan.principle = data["principle"]
                edit = True
            if data["tenure"]:
                loanold.tenure = loan.tenure
                loan.tenure = data["tenure"]
                edit = True
        if edit:
            loan.edit_date = datetime.datetime.utcnow().date()
            loan.edit_uid = current_user.id
            db.session.commit()
            return jsonify({"message": "Loan Edited"})
        else:
            return jsonify({"message": "Loan not edited"})
    else:
        return jsonify({"message": "Loan not found"})
