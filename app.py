from flask import Flask,flash,redirect, render_template,request,session,url_for
import sqlite3
from flask_sqlalchemy import SQLAlchemy
import os
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import InputRequired, Length, ValidationError, Email


#how do we remove the ability for users to navigate to different pages like login after they are logged in 

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database2.db'
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
Session(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

    def __init__(self,username,password):
        self.username = username
        self.password = password

class RegisterForm(FlaskForm):
    
    #may want to remove default error messages so formatting is consistent
    #add password confirmation field
    username = EmailField(validators=[InputRequired(),Length(min=4,max=20),Email("Please enter a valid email")],render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")
    
    def validate_username(self,username):
        existing_user_username = Users.query.filter_by(
        username=username.data).first()
        
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')
    
    def validate_password(self, password):
        password = password.data
        SpecialSym = ['$', '@', '#', '%']
        if not any(char.isdigit() for char in password):
            raise ValidationError("Password should have at least one numeral")

        if not any(char.isupper() for char in password):
            raise ValidationError('Password should have at least one uppercase letter')

        if not any(char.islower() for char in password):
            raise ValidationError('Password should have at least one lowercase letter')

        if not any(char in SpecialSym for char in password):
            raise ValidationError('Password should have at least one of the symbols $@#')


class LoginForm(FlaskForm):
    
    #may want to remove default error messages so formatting is consistent
    username = EmailField(validators=[InputRequired(),Length(min=4,max=20),Email("Please enter a valid email")],render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

   

   
@app.route("/")
def index():
        return render_template("index.html")


@app.route("/register",methods=["GET","POST"])
def register():
    error = None
    form = RegisterForm()
    if request.method == "POST":
        if form.validate_on_submit():
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
            new_user = Users(username=form.username.data,password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect("/home")
    return render_template("register.html",form=form)


@app.route("/login",methods=["GET","POST"])
def login():
    
    form = LoginForm()
    error = None
    if request.method == "POST":
        if form.validate_on_submit():
            user = Users.query.filter_by(username = form.username.data).first()
            if user:
                if check_password_hash(user.password,form.password.data):
                    login_user(user)
                    return redirect("/home")
            error = ("Your username or password is incorrect")
    return render_template("login.html", form = form, error = error)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

    


@app.route("/home",methods=["GET","POST"])
@login_required
def home():
        return render_template("home.html")
   


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


if __name__ == "__main__":
    app.run(debug=True)