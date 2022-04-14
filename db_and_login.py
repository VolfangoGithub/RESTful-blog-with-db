from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, ForeignKey
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask import Flask
from main import db, login_manager

USER_EXISTS = "USER_EXISTS"
USER_LOGGED_IN = "USER_LOGGED_IN"
USER_NOT_KNOWN = "USER_NOT_KNOWN"
USER_REGISTERED = "USER_REGISTERED"
INVALID_PASSWORD = "INVALID_PASSWORD"

is_initialized = False

# Following out commented code tried to define and initialize db and login_manager
# in a separate module. This works fine until trying to store a relationship
# (here comment to a post) in the DB. An error with the session occurs:
# "Comment is already assigned to another session"
# ==> needs further investigation, maybe using "contexts", see Flask_SQLAlchemy docs

# db = SQLAlchemy()
# login_manager = LoginManager()


# def init(app):
#     # global db
#     global is_initialized
#     if not is_initialized:
#         ##CONNECT TO DB
#         app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
#         app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#         db = SQLAlchemy(app)
#         # Prepare for login
#         login_manager.init_app(app)
#         is_initialized = True



##CONFIGURE TABLES

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

def register_and_login(email, name, password):
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


def register(email, name, password):
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


def login(email, password):
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


def logout():
    logout_user()


def get_current_user():
    return current_user


def get_all_posts():
    print(db.session)
    return BlogPost.query.all()


def get_post_by_id(post_id):
    print(db.session)
    return BlogPost.query.get(post_id)


def create_new_post(title, subtitle, body, img_url, author, date):
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


def update_post():
    db.session.commit()


def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()


def create_new_comment(comment, author, parent_post: BlogPost):
    new_comment = Comment(
        text=comment,
        comment_author=author,
        parent_post=parent_post
    )

    db.session.add(new_comment)
    db.session.commit()
