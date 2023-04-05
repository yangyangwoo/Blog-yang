import datetime
import os

from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_ckeditor import CKEditor, CKEditorField
from forms import RegistertForm, CreatePostForm, LoginForm, CommentForm
# password module
from werkzeug.security import generate_password_hash, check_password_hash
# flask_login module
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
# for custom function decorator
from functools import wraps
# for relational database
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

from flask_gravatar import Gravatar

# CREATE FLASK APP, SET WTFORM KEY, BIND BOOTSTRAP, CKEDITOR TO APP
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=50, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

# CONNECT TO EXISTING DB AND TABLE
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# CREATE LOGIN MANAGER, BIND IT TO APP
login_manager = LoginManager()
login_manager.init_app(app)

# CONFIGURE MODEL CLASS FOR USER DATA
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    # Create reference to the BlogPost object, refers to the author property in the BlogPost class.
    # the posts property is now a BlogPost object.
    child_posts = relationship('BlogPost', back_populates='parent_author')
    # Create reference to Comment object, refer to user property in Comment class
    child_comments = relationship('Comment', back_populates='parent_author')


# CONFIGURE MODEL CLASS THAT MAPS TO THE EXISTING TABLE "blog_post" IN DATABASE
class BlogPost(db.Model):
    __tablename__ = 'blog_post'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=False, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    # author = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # Create Foreign Key, 'users.id' users refer to the table name of User class.
    parent_author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # Create reference to the User object, the "posts" refers to the posts property in the User class.
    # the author property is now a User object.
    parent_author = relationship('User', back_populates='child_posts')
    # Create a list of comments object
    child_comments = relationship('Comment', back_populates="parent_post")


# CONFIGURE MODEL CLASS FOR COMMENT DATA
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    # Create Foreign Key, 'users.id' users refer to the table name of User class.
    parent_author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # Create reference to User object, refer to comments property in Comment class
    parent_author = relationship('User', back_populates='child_comments')
    # Create ForeignKey of 'blog_post.id'
    parent_post_id = db.Column(db.Integer, db.ForeignKey('blog_post.id'))
    # Create BlogPost object, refer to post_comments property in BlogPost class
    parent_post = relationship('BlogPost', back_populates='child_comments')


# define a func decorator
def admin_only(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(403)
        elif current_user.id != 1:
            abort(403)
        return func(*args, **kwargs)
    return decorated_function


# @app.before_request
# def create_table():
#     db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register', methods=['POST', 'GET'])
def register():
    error = None
    new_user = User()
    form = RegistertForm()
    if form.validate_on_submit():
        new_user.email = form.email.data
        hashed_salted_password = generate_password_hash(
            password=form.password.data,
            method='pbkdf2:sha256',
            salt_length=6
        )
        new_user.password = hashed_salted_password
        new_user.name = form.name.data
        if not User.query.filter_by(email=new_user.email).first():
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("get_all_posts"))
        else:
            # Send flash messsage
            flash("You've already signed up with that email, log in instead!.")
            return redirect(url_for('login'))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        input_email = request.form['email']
        input_password = request.form['password']
        user = User.query.filter_by(email=input_email).first()
        if user:
            # Check stored password hash against entered password hashed.
            if check_password_hash(pwhash=user.password, password=input_password):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Password incorrect, please try again.')
                return redirect(url_for('login'))
        else:
            flash("User does not exist, please try again.")
            return redirect(url_for('login'))
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

@app.route('/')
def get_all_posts():
    posts = db.session.query(BlogPost).all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route("/post/<int:index>", methods=['POST', 'GET'])
def show_post(index):
    requested_post = BlogPost.query.filter_by(id=index).first()
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('You need to login to comment.')
            return redirect(url_for("login"))

        new_comment = Comment(
            text=request.form.get('comment_text'),
            parent_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, form=form)


@app.route("/edit/<int:post_id>", methods=['POST', 'GET'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    # pre-fill a form using Flask and WTForms by passing initial data to the form constructor.
    # the CreatePostForm is being pre-filled with data from a BlogPost object retrieved from the database.
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        author=post.author_id,
        body=post.body,
        img_url=post.img_url
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = request.form.get('subtitle')
        post.author = current_user.id
        post.body = request.form.get('body')
        post.img_url = request.form.get('img_url')
        db.session.commit()
        return redirect(url_for('show_post', index=post_id))
    return render_template("make-post.html", post=post, form=edit_form, is_edit=True, logged_in=current_user.is_authenticated)


@app.route('/new-post', methods=['POST', 'GET'])
@admin_only
def make_post():
    form = CreatePostForm(author=current_user.id)
    if request.method == 'POST':
        # soup = BeautifulSoup(body, 'html.parser')
        # body_text = soup.get_text()
        new_post = BlogPost(
            title=request.form.get('title'),
            subtitle=request.form.get('subtitle'),
            parent_author_id=current_user.id,
            date=datetime.date.today().strftime("%B %d, %Y"),
            body=form.body.data,
            img_url=request.form.get('img_url')
        )
        db.session.add(new_post)
        db.session.commit()
        # print(blog_content)
        return redirect(url_for('get_all_posts'))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/delete/<int:post_id>')
@admin_only
def delete_post(post_id):
    post = BlogPost.query.get(post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.getenv('PORT')))