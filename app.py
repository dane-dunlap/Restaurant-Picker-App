from flask import Flask,flash,redirect, render_template,request,session,url_for
import sqlite3
from flask_sqlalchemy import SQLAlchemy
import os
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, BooleanField
from wtforms.validators import InputRequired, Length, ValidationError, Email,EqualTo
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_mail import Mail 
from flask_mail import Message
import myEnVal

#Configuring flask app and sqlalchemy DB
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
Session(app)

#Configuring LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

#configuring Flask Mail
myEnVal.setVar()
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['TESTING'] = False
MAIL_SUPPRESS_SEND = False
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASSWORD')
MAIL_DEBUG = True
mail = Mail(app)


print(os.environ.get('EMAIL_USER'))
print(os.environ.get('EMAIL_PASSWORD'))



@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    firstname = db.Column(db.String(20),nullable=False)
    lastname = db.Column(db.String(20),nullable=False)


    def __init__(self,username,password,firstname,lastname):
        self.username = username
        self.password = password
        self.firstname= firstname
        self.lastname = lastname

    def get_reset_token(self):
        s = Serializer(app.config['SECRET_KEY'])
        return s.dumps({'user_id':self.id})

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return Users.query.get(user_id)


class RegisterForm(FlaskForm):
    
    firstname=StringField(validators=[InputRequired()],render_kw={"placeholder": "First Name","class": "form-control rounded-pill border-0 shadow-sm px-4"})
    lastname=StringField(validators=[InputRequired()],render_kw={"placeholder": "Last Name","class": "form-control rounded-pill border-0 shadow-sm px-4"})
    username = EmailField(validators=[InputRequired(),Email("Please enter a valid email")],render_kw={"placeholder": "Email","class": "form-control rounded-pill border-0 shadow-sm px-4"})
    password = PasswordField(validators=[InputRequired(),Length(min=4,max=20),EqualTo("confirmation",message="Passwords must match")],render_kw={"placeholder": "Password","class": "form-control rounded-pill border-0 shadow-sm px-4"})
    confirmation = PasswordField(render_kw={"placeholder": "Confirm your password","class": "form-control rounded-pill border-0 shadow-sm px-4"})
    accept_tos = BooleanField('I accept the TOS', validators=[InputRequired()])
    submit = SubmitField("Register",render_kw={"class": "btn btn-primary btn-block text-uppercase mb-2 rounded-pill shadow-sm"})


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
    username = EmailField(validators=[InputRequired(),Email("Please enter a valid email")],render_kw={"placeholder": "Email","class": "form-control rounded-pill border-0 shadow-sm px-4"})
    password = PasswordField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder": "Password","class": "form-control rounded-pill border-0 shadow-sm px-4"})
    submit = SubmitField("Login",render_kw={"class": "btn btn-primary btn-block text-uppercase mb-2 rounded-pill shadow-sm"})

   
class RequestResetForm(FlaskForm):
    username = EmailField(validators=[InputRequired(),Email("Please enter a valid email")],render_kw={"placeholder": "Email","class": "form-control rounded-pill border-0 shadow-sm px-4"})
    submit = SubmitField("Request password reset",render_kw={"class": "btn btn-primary btn-block text-uppercase mb-2 rounded-pill shadow-sm"})

    def validate_username(self,username):
        existing_user_username = Users.query.filter_by(
        username=username.data).first()
        
        if existing_user_username is None:
            raise ValidationError('There is no account associated with this email. Please register first')
        
   
class ResetPasswordForm(FlaskForm):
    password = PasswordField(validators=[InputRequired(),Length(min=4,max=20),EqualTo("confirmation",message="Passwords must match")],render_kw={"placeholder": "Password","class": "form-control rounded-pill border-0 shadow-sm px-4"})
    confirmation = PasswordField(render_kw={"placeholder": "Confirm your password","class": "form-control rounded-pill border-0 shadow-sm px-4"})
    submit = SubmitField("Reset Password",render_kw={"class": "btn btn-primary btn-block text-uppercase mb-2 rounded-pill shadow-sm"})


@app.route("/")
def index():
        return redirect(url_for("login"))


@app.route("/register",methods=["GET","POST"])
def register():
    form = RegisterForm()
    if request.method == "POST":
        
        if form.validate_on_submit():
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
            new_user = Users(username=form.username.data,password=hashed_password,firstname=form.firstname.data,lastname=form.lastname.data)
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

@app.route("/terms")
def terms():
        return render_template("terms.html")



@app.route("/home",methods=["GET","POST"])
@login_required
def home():
        return render_template("home.html")
   

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',sender='noreply@demo.com',recipients=[user.username])
    msg.body = f'''To reset your password, visit the following link:
    {url_for('reset_password',token=token,_external=True)}

    If you did not make this request, please ignore this email.
    '''
    mail.send(msg)
    

@app.route("/reset_request",methods=["GET","POST"])
def reset_request():
    form = RequestResetForm()
    if request.method == "POST":
        if form.validate_on_submit():
            user=Users.query.filter_by(username=form.username.data).first()
            send_reset_email(user)
            flash('An email has been sent with instructions to reset your password','info')
            
            return redirect(url_for('login'))
    
    return render_template('reset_request.html',form=form)

    
@app.route("/reset_password/<token>",methods=["GET","POST"])
def reset_password(token):
    user = Users.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token','warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
            user.password = hashed_password
            db.session.commit()
            flash('Your password has been updated! You are now able to log in')
            return redirect("/home") 
    return render_template('reset_password.html',form=form)

  
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