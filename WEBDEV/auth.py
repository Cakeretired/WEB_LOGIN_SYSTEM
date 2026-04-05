from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method== 'POST':
        email = request.form.get('email')
        password = request.form.get('password')


        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):

                login_user(user, remember=True)
                flash('logged in successfully', category='success')
                return redirect(url_for('views.home'))



            else:
                flash('wrong password try again', category='danger')
        else:
            flash('Email does not exist', category='danger')

    return render_template('login.html', user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login', ))

@auth.route('/signup', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password1 = request.form.get('password')
        password2 = request.form.get('confirm_password')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('This user already exists', category='danger')

        elif password1 != password2:
            flash("Passwords don't match", category="danger")

        elif not password1:
            flash("Please input a password", category="danger")

        elif not password2:
            flash("Please confirm your password", category="danger")

        elif not email or len(email) < 4:
            flash("Please enter a valid email", category="danger")

        elif not username or len(username) < 2:
            flash("Please enter a valid username", category="danger")

        else:
            new_user = User(email= email, username=username, password=generate_password_hash(password1, method='pbkdf2:sha256'))

            db.session.add(new_user)
            db.session.commit()
            flash("Account created successfully", category="success")
            login_user(new_user, remember=True)
            return redirect(url_for('views.home'))

    return render_template('signup.html', user= current_user)
