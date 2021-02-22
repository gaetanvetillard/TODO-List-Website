from threading import TIMEOUT_MAX
from flask import Flask, render_template, redirect, url_for, flash, abort, Markup, request
import flask
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relation, relationship
from flask_sqlalchemy import SQLAlchemy
from forms import LoginForm, RegisterForm
from functools import wraps
from datetime import date, timedelta
from sqlalchemy import asc


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
Bootstrap(app)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo_list_users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    todo_items = relationship("Item", back_populates="owner")


class Item(db.Model):
    __tablename__ = 'items'
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    owner = relationship("User", back_populates="todo_items")
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.String(250), nullable=False)

db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


def already_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            return render_template('denied.html')
        return f(*args, **kwargs)
    return decorated_function


def need_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return render_template('denied.html')
        return f(*args, **kwargs)
    return decorated_function


@app.route('/', methods=['GET', 'POST'])
def home():
    expired = []
    todo_list = []
    if current_user.is_authenticated:
        todo_list = Item.query.filter_by(owner=current_user).order_by(asc(Item.date)).all()
        for item in todo_list:
            item_date = item.date.split("-")
            today_date = date.today().strftime("%Y-%m-%d").split('-')
            for i in range(3):
                if item_date[i] < today_date[i]:
                    expired.append(item)
                    todo_list.remove(item)

    return render_template('index.html', current_user=current_user, todo=todo_list, expired=expired)


@app.route('/login', methods=["GET", "POST"])
@already_login
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        if not user:
            flash(f"No account found with {email}. <a href='/register'>Sign up for free.</a>")
            return redirect(url_for("login"))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for("home"))

    return render_template('login.html', form=form, current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
@already_login
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("You're already registered with this email.")
            return redirect(url_for("register"))

        if User.query.filter_by(username=form.username.data).first():
            flash("You're already registered with this username.")
            return redirect(url_for("register"))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8,
        )
        new_user = User(
            email=form.email.data,
            username=form.username.data,
            password=hash_and_salted_password
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('home'))

    return render_template('register.html', form=form, current_user=current_user)


@app.route('/logout')
def logout():
    print(current_user.id)
    logout_user()
    return redirect(url_for('home'))


@app.route('/add-todo-item', methods=["GET", "POST"])
@need_login
def new_item():
    if request.form['date'] != "":
        date_ = request.form['date']
    else:
        tomorrow = date.today() + timedelta(days=1)
        date_ = tomorrow.strftime("%Y-%m-%d")
    new_item = Item(
        owner=current_user,
        text = request.form["item"],
        date = date_,
    )
    db.session.add(new_item)
    db.session.commit()
    return redirect(url_for('home'))


@app.route('/delete/<int:id>', methods=['GET', 'POST'])
@need_login
def delete(id):
    item_to_delete = Item.query.get(id)
    db.session.delete(item_to_delete)
    db.session.commit()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)