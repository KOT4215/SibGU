from flask import Flask, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import DataRequired, EqualTo, ValidationError
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

login_manager = LoginManager(app)
login_manager.login_view = 'login'


def load_users():
    try:
        with open('users.json', 'r') as f:
            return json.load(f).get('users', [])
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_users(users):
    with open('users.json', 'w') as f:
        json.dump({'users': users}, f, indent=4, default=str)


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])

    def validate_username(self, field):
        if any(user['username'] == field.data for user in load_users()):
            raise ValidationError('Username already taken')

    def validate_password(self, field):
        password = field.data
        if len(password) < 8:
            raise ValidationError('Password must be at least 8 characters')
        if not any(c.isdigit() for c in password):
            raise ValidationError('Password must contain a number')
        if not any(c.isupper() for c in password):
            raise ValidationError('Password must contain an uppercase letter')
        if not any(c.islower() for c in password):
            raise ValidationError('Password must contain a lowercase letter')


class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['username']
        self.user_data = user_data

    @staticmethod
    def get(username):
        users = load_users()
        user_data = next((u for u in users if u['username'] == username), None)
        return User(user_data) if user_data else None


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('create_user'))

    form = LoginForm()
    if form.validate_on_submit():
        users = load_users()
        user_data = next((u for u in users if u['username'] == form.username.data), None)

        if user_data and check_password_hash(user_data['password_hash'], form.password.data):
            user = User(user_data)
            login_user(user, remember=form.remember.data)

            user_data['last_login_date'] = datetime.now().isoformat()
            save_users(users)

            return redirect(url_for('create_user'))
        flash('Invalid username or password')

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('create_user'))

    form = RegisterForm()
    if form.validate_on_submit():
        users = load_users()
        new_user = {
            'username': form.username.data,
            'password_hash': generate_password_hash(form.password.data),
            'registration_date': datetime.now().isoformat(),
            'last_login_date': None
        }
        users.append(new_user)
        save_users(users)
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))

    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{error}")

    return render_template('register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    form = RegisterForm()
    if form.validate_on_submit():
        users = load_users()
        new_user = {
            'username': form.username.data,
            'password_hash': generate_password_hash(form.password.data),
            'registration_date': datetime.now().isoformat(),
            'last_login_date': None
        }
        users.append(new_user)
        save_users(users)
        flash('User created successfully')
        return redirect(url_for('create_user'))

    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{error}")

    return render_template('create_user.html', form=form)


if __name__ == '__main__':
    if not os.path.exists('users.json'):
        with open('users.json', 'w') as f:
            json.dump({'users': []}, f)
    app.run(debug=True)