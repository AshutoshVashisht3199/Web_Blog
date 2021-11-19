from flask import render_template, url_for, flash, redirect, request, Blueprint
from flask_login import login_user, current_user, logout_user, login_required
from test import db, bcrypt
from test.models import User, Post
from test.users.forms import (RegistrationForm, LoginForm, UpdateAccountForm,
                                   RequestResetForm, ResetPassword)
from test.users.utils import save_picture, send_reset_email



from flask import Blueprint
users = Blueprint('users',__name__)


@users.route("/register", methods=['Get','Post'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.hello_world'))
    form=RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User( username = form.username.data, email = form.email.data, password = hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Your account has been created! you are now able to log in', 'success')
        return redirect(url_for('users.login'))
    return render_template('register.html', title = 'register', form = form)

@users.route("/login" , methods=['Get','Post'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.hello_world'))
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password,form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.hello_world'))    
        flash('Login unsuccessful.Please check your username and password', 'danger')
    return render_template('login.html', title = 'login', form = form)

@users.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('main.hello_world'))

@users.route("/account",methods=['Get','Post'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('your account has been updated', 'success')
        return redirect(url_for('users.account'))
    elif request.method == 'GET':
            form.username.data = current_user.username
            form.email.data = current_user.email
    image_file = url_for('static', filename = 'profile_pics/' + current_user.image_file)
    return render_template('account.html', title = 'account',image_file=image_file, form = form)


@users.route("/user/<string:username>")
def user_posts(username):
    page = request.args.get('page', default=1,type=int)
    user = User.query.filter_by(username=username).first_or_404()
    posts=Post.query.filter_by(author=user)\
            .order_by(Post.date_posted.desc())\
            .paginate(page=page,per_page=2)
    return render_template('user_posts.html',posts=posts,user=user) 

@users.route("/reset_password",methods=['Get','Post'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.hello_world'))
    form=RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('users.login'))
    return render_template('reset_request.html',tilte='Reset Password',form=form) 

@users.route("/reset_password/<token>",methods=['Get','Post'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.hello_world'))
    user=User.verify_reset_token(token)
    if user is None:
        flash('that is an invalid or expired token', 'warning')
        return redirect(url_for('users.reset_request'))
    form=ResetPassword()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash(f'Your password has been updated, you are now able to log in', 'success')
        return redirect(url_for('users.login'))
    return render_template('reset_token.html',tilte='Reset Password',form=form)


