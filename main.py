from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date

from flask_wtf import FlaskForm
from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import current_user, login_required, LoginManager
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired

from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import db_and_login as dl


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

# dl.init(app)


@login_manager.user_loader
def load_user(user_id):
    return dl.User.query.get(int(user_id))

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
    posts = dl.get_all_posts()
    is_admin = False
    logged_in = current_user.is_authenticated
    if logged_in:
        is_admin = (current_user.id == 1)
    return render_template("index.html", all_posts=posts, logged_in=logged_in, is_admin=is_admin)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        reg_result = dl.register_and_login(request.form.get('email'), request.form.get('name'),
                                           request.form.get('password'))
        if reg_result == dl.USER_EXISTS:
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        if reg_result == dl.USER_LOGGED_IN:
            return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        login_result = dl.login(email, password)
        print(login_result)
        if login_result == dl.USER_LOGGED_IN:
            flash('You were successfully logged in')
            return redirect(url_for('get_all_posts'))

        if login_result == dl.INVALID_PASSWORD:
            flash('Invalid password')
            return redirect(url_for('login'))

        if login_result == dl.USER_NOT_KNOWN:
            flash('Your email account is not known.')
            return redirect(url_for('login'))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    dl.logout()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = dl.get_post_by_id(post_id)
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
            dl.create_new_comment(
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
        new_post = dl.create_new_post(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", endpoint="edit_post")
@admin_only
def edit_post(post_id):
    post = dl.get_post_by_id(post_id)
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        dl.update_post()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>", endpoint="delete_post")
@admin_only
def delete_post(post_id):
    dl.delete_post(post_id)
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    # app.run(host='0.0.0.0', port=5000)
    app.run()
