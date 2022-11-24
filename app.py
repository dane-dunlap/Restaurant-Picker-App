from flask import Flask,flash,redirect, render_template,request,session
import sqlite3
from flask_sqlalchemy import SQLAlchemy
import os
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError


#testing new branch creation
currentdirectory = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/daned/OneDrive/Documents/Coding Project/database.db'
db = SQLAlchemy(app)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['SECRET_KEY'] = 'thisisasecretkey'
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


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder": "Email"})
    password = StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self,username):
        existing_user_username = Users.query.filter_by(
        username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')
        

@app.route("/")
def index():
        return render_template("index.html")


@app.route("/register",methods=["GET","POST"])
def register():
    
    form = RegisterForm()
    #connection = sqlite3.connect(currentdirectory + "\data.db")
    #cursor = connection.cursor()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        #cursor.execute("INSERT INTO users(username,hash) VALUES(?,?)",(form.username.data, hashed_password,))
        #connection.commit()
        return redirect("/home")
    
    return render_template("register.html",form=form)

        

@app.route("/home",methods=["GET","POST"])
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
    with app.app_context():
        db.create_all()
    app.run()