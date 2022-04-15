from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date

from flask_wtf import FlaskForm
from sqlalchemy import ForeignKey, Integer
from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import current_user, login_required, LoginManager, UserMixin, login_user, logout_user
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired

from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import os

# import db_and_login as dl


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
# app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)



# **************************************************************************
# START
# PART, WHICH HAS BEEN ORIGINALLY IN db_and_login.py
# **************************************************************************
USER_EXISTS = "USER_EXISTS"
USER_LOGGED_IN = "USER_LOGGED_IN"
USER_NOT_KNOWN = "USER_NOT_KNOWN"
USER_REGISTERED = "USER_REGISTERED"
INVALID_PASSWORD = "INVALID_PASSWORD"


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(Integer, ForeignKey('user.id'))

    # Create reference to the User object, the "posts" refers to the
    # posts property in the User class.
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    #***************Parent Relationship*************#
    comments = relationship("Comment", back_populates="parent_post")


class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    # Create reference to the User object, the "posts" refers to the
    # posts property in the User class.
    comment_author = relationship("User", back_populates="comments")

    #***************Child Relationship*************#
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)


# Run following code to generate the DB
# db.create_all()

def dl_register_and_login(email, name, password):
    if User.query.filter_by(email=email).first():
        # User already exists
        return USER_EXISTS

    new_user = User(
        email=email,
        name=name,
        password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=8))

    db.session.add(new_user)
    db.session.commit()

    print(db.session)

    # Log in and authenticate user after adding details to database.
    login_user(new_user)

    return USER_LOGGED_IN


def dl_register(email, name, password):
    if User.query.filter_by(email=email).first():
        # User already exists
        return USER_EXISTS

    new_user = User(
        email=email,
        name=name,
        password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=8))

    db.session.add(new_user)
    db.session.commit()

    return USER_REGISTERED


def dl_login(email, password):
    # Find user by email entered.
    user = User.query.filter_by(email=email).first()

    if user:
        # Check stored password hash against entered password hashed.
        if check_password_hash(user.password, password):
            login_user(user)
            return USER_LOGGED_IN
        else:
            return INVALID_PASSWORD

    else:
        return USER_NOT_KNOWN


def dl_logout():
    logout_user()


def dl_get_current_user():
    return current_user


def dl_get_all_posts():
    print(db.session)
    return BlogPost.query.all()


def dl_get_post_by_id(post_id):
    print(db.session)
    return BlogPost.query.get(post_id)


def dl_create_new_post(title, subtitle, body, img_url, author, date):
    print(db.session)
    new_post = BlogPost(
        title=title,
        subtitle=subtitle,
        body=body,
        img_url=img_url,
        author=author,
        date=date
    )

    print(db.session)
    db.session.add(new_post)
    db.session.commit()


def dl_update_post():
    db.session.commit()


def dl_delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()


def dl_create_new_comment(comment, author, parent_post: BlogPost):
    new_comment = Comment(
        text=comment,
        comment_author=author,
        parent_post=parent_post
    )

    db.session.add(new_comment)
    db.session.commit()

# **************************************************************************
# END
# PART, WHICH HAS BEEN ORIGINALLY IN db_and_login.py
# **************************************************************************

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Decorator
def admin_only(func):
    # wraps(func)
    print(func.__name__)

    def wrapper_admin(*args, **kwargs):
        if current_user.is_authenticated:
            if current_user.id == 1:
                print("is admin")
                return func(*args, **kwargs)
            else:
                # 403 = Forbidden
                print("is forbidden")
                return abort(403)
        else:
            # 403 = Forbidden
            print("is forbidden")
            return abort(403)

    return wrapper_admin


@app.route('/')
def get_all_posts():
    posts = dl_get_all_posts()
    is_admin = False
    logged_in = current_user.is_authenticated
    if logged_in:
        is_admin = (current_user.id == 1)
    return render_template("index.html", all_posts=posts, logged_in=logged_in, is_admin=is_admin)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        reg_result = dl_register_and_login(request.form.get('email'), request.form.get('name'),
                                           request.form.get('password'))
        if reg_result == USER_EXISTS:
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        if reg_result == USER_LOGGED_IN:
            return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        login_result = dl_login(email, password)
        print(login_result)
        if login_result == USER_LOGGED_IN:
            flash('You were successfully logged in')
            return redirect(url_for('get_all_posts'))

        if login_result == INVALID_PASSWORD:
            flash('Invalid password')
            return redirect(url_for('login'))

        if login_result == USER_NOT_KNOWN:
            flash('Your email account is not known.')
            return redirect(url_for('login'))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    dl_logout()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = dl_get_post_by_id(post_id)
    logged_in = current_user.is_authenticated
    if logged_in:
        is_admin = (current_user.id == 1)
    else:
        is_admin = False
    if form.validate_on_submit():
        if not logged_in:
            flash("Please login or register for comment")
            return redirect(url_for("login"))
        else:
            dl_create_new_comment(
                comment=form.comment.data,
                author=current_user,
                parent_post=requested_post
            )
    return render_template("post.html", form=form, post=requested_post, is_admin=is_admin, logged_in=logged_in)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")

# Without adding parameter "endpoint" to app.route, the additional decorator admin_only
# leads to an AssertionError, when admin_only is added to more than one method!
@app.route("/new-post", methods=["GET", "POST"], endpoint="add_new_post")
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = dl_create_new_post(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"], endpoint="edit_post")
@admin_only
def edit_post(post_id):
    post = dl_get_post_by_id(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        dl_update_post()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>", endpoint="delete_post")
@admin_only
def delete_post(post_id):
    delete_post(post_id)
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    # app.run(host='0.0.0.0', port=5000)
    app.run()
