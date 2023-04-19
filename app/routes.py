
# Modules
from app import app
from flask import render_template, request, redirect, flash, url_for
from flask_login import LoginManager, UserMixin, current_user, logout_user, login_user, login_required
from flask_wtf import FlaskForm
from wtforms import SubmitField, BooleanField, StringField, PasswordField, IntegerField, FloatField, HiddenField
from wtforms.validators import DataRequired, ValidationError, EqualTo
# import app
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os

# Database
app.config['SECRET_KEY'] = 'flaskExam'
basedir = os.path.abspath(os.path.dirname(__file__))
app.app_context().push()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(basedir, 'data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
Migrate(app, db)

# Menu
menu = [{"name": "Register", "url": "register"},
        {"name": "Login", "url": "login"},
        {"name": "Groups", "url": "groups"}]

# Login
login_manager = LoginManager(app)
login_manager.login_view = 'register'
login_manager.login_message_category = 'info'
bcrypt = Bcrypt(app)

# Registration and login forms

# Users database
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    fullname = db.Column("Fullname", db.String(), unique=True, nullable=False)
    email = db.Column("Email", db.String(), unique=True, nullable=False)
    password = db.Column("Password", db.String(60),
                         unique=True, nullable=False)
    repeat_password = db.Column(
        "Repeat password", db.String(60), unique=True, nullable=False)

    def __init__(self, fullname, email, password, repeat_password):
        self.fullname = fullname
        self.email = email
        self.password = password
        self.repeat_password = repeat_password

    def __repr__(self):
        return f"{self.id} {self.fullname} {self.email} {self.password}, {self.repeat_password}"

    # Group database
class Group(db.Model):
    __tablename__ = "groups"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    group_name = db.Column(db.String(), nullable=False)

    def __init__(self, group_name, user_id):
        self.user_id = user_id
        self.group_name = group_name

    def __repr__(self):
        return f"{self.id} {self.group_name} {self.user_id}"

    # Bills database
class Bills(db.Model):
    __tablename__ = 'bills'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey(
        'groups.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(), nullable=False)

    def __init__(self, user_id, group_id, amount, description):
        self.user_id = user_id
        self.group_id = group_id
        self.amount = amount
        self.description = description

    def __repr__(self):
        return f"{self.id}{self.user_id} {self.group_id} {self.amount} {self.description}"

    # Registration form
class RegistrationForm(FlaskForm):
    fullname = StringField('Fullname', [DataRequired()])
    email = StringField('Email', [DataRequired()])
    password = PasswordField('Password', [DataRequired()])
    repeat_password = PasswordField("Repeat password", [EqualTo(
        'password', "Error, passwords should match each other")])
    submit = SubmitField('Register')

# Login form
class LoginForm(FlaskForm):
    email = StringField('Email', [DataRequired()])
    password = PasswordField('Password', [DataRequired()])
    remember = BooleanField("Remember me")
    submit = SubmitField('Login')

# Groups form
class AddGroupForm(FlaskForm):
    group_name = StringField('Group name')
    submit = SubmitField('Add')

# Bills form
class AddBillForm(FlaskForm):
    amount = FloatField('Amount:', [DataRequired()])
    description = StringField('Description:', [DataRequired()])
    group_id = HiddenField()
    submit = SubmitField('Add')

# Login manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Homepage
@app.route('/')
def index():
    return render_template('public/index.html', title="Home page", title2="Split bill", title3="BEST IN MARKET", menu=menu)

# Registration page
@app.route("/register", methods=['GET', 'POST'])
def register():
    db.create_all()
    if current_user.is_authenticated:
        return redirect(url_for('register'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user = User(fullname=form.fullname.data, email=form.email.data,
                    password=user_password, repeat_password=user_password)

        # Check fullname and email
        existing_fullname = User.query.filter_by(
            fullname=form.fullname.data).first()
        if existing_fullname is not None:
            flash('This name already exists. Please, choose another.', 'error')
            return redirect('/register')
        existing_email = User.query.filter_by(email=form.email.data).first()
        if existing_email is not None:
            flash('This email already exists. Please, choose another.', 'error')
            return redirect('/register')
        # Add to database
        db.session.add(user)
        db.session.commit()
        flash('Successfuly registered!', 'success')
        return redirect(url_for('register'))
    return render_template('public/register.html', title='Register', title2="Split bill", title3="BEST IN MARKET", menu=menu, form=form)

# Login page
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('groups'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('groups'))
        else:
            flash('Login failed. Check your email or password', 'danger')
    return render_template('public/login.html', title="Login", title2="Split bill", title3="BEST IN MARKET", menu=menu, form=form)

# Log off
@app.route("/logoff")
def logoff():
    logout_user()
    return redirect(url_for('index'))

# Groups page
@app.route("/groups", methods=['GET', 'POST'])
@login_required
def groups():
    db.create_all()
    form = AddGroupForm()
    try:
        all_groups = Group.query.filter_by(user_id=current_user.id).all()
    except:
        all_groups = []
    # print(all_groups)
    return render_template('public/groups.html', title="Groups", title2="Select your group", menu=menu, form=form, all_groups=all_groups)

@app.route("/new_group", methods=["GET", "POST"])
@login_required
def new_group():
    group_name = request.form['group_name']
    new_group = Group(group_name=group_name, user_id=current_user.id)
    db.session.add(new_group)
    db.session.commit()
    flash("Successfuly created group", 'success')
    return redirect(url_for('groups'))

# Bills page
@app.route("/bills/<int:id>", methods=['GET', 'POST'])
@login_required
def bills(id):
    # db.create_all()
    form = AddBillForm()
    bills = Bills.query.filter_by(group_id=id).all()
    return render_template("public/bills.html", title="Bill", title2 = "Your bills", form=form, menu=menu, bills=bills, id=id)

@app.route("/new_bill", methods=['POST'])
@login_required
def new_bill():
    form = AddBillForm(request.form)
    if form.validate():
        group_id = request.args.get('group_id')
        amount = form.amount.data
        description = form.description.data
        new_bill = Bills(user_id=current_user.id, group_id=group_id, amount=amount, description=description)
        db.session.add(new_bill)
        db.session.commit()
        flash("Successfully added bill", 'success')
        return redirect(url_for('bills', id=group_id))
    else:
        flash("Error adding bill", 'danger')
        return redirect(url_for('bills', id=form.group_id.data))
