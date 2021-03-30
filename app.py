#!/usr/bin/env python3
import models
import forms
import sys
import logging

from flask import (Flask, g, render_template, flash, redirect, url_for,
                  abort)
from flask_bcrypt import check_password_hash
from flask_login import (LoginManager, login_user, logout_user,
                        login_required, current_user)


app = Flask(__name__)

app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.ERROR)

app.secret_key = 'wtlejlp[y6uogdrHJKphplrpjh[rpjh[r]]]%$R^&Y(1013r9fjlfqefgklejm)'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(userid):
    try:
        return models.User.get(models.User.id == userid)
    except models.DoesNotExist:
        return None


@app.before_request
def before_request():
    """Connect to the database before each request."""
    g.db = models.db
    g.db.connect()
    g.user = current_user


@app.after_request
def after_request(response):
    """Close the database connection after each request."""
    g.db.close()
    return response


@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404


@app.route('/register', methods=('GET', 'POST'))
def register():
    form = forms.RegisterForm()
    if form.validate_on_submit():
        flash("Yay, you registered!", "success")
        models.User.create_user(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data
        )
        return redirect(url_for('index'))
    return render_template('register.html', form=form)


@app.route('/login', methods=('GET', 'POST'))
def login():
    form = forms.LoginForm()
    if form.validate_on_submit():
        try:
            user = models.User.get(models.User.email == form.email.data)
        except models.DoesNotExist:
            flash("Your email or password doesn't match!", "error")
        else:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                flash("You've been logged in!", "success")
                return redirect(url_for('index'))
            else:
                flash("Your email or password doesn't match!", "error")
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You've been logged out! Come back soon!", "success")
    return redirect(url_for('index'))


# / - Known as the root page, homepage, landing page but will act as the Listing route.
# /entries - Also will act as the Listing route just like /
@app.route('/')
@app.route('/entries')
def index():
    stream = models.Journal.select().order_by(models.Journal.date_updated.desc())
    return render_template('index.html', stream=stream)


@app.route('/tag/<tag>')
def Retrieve_By_Tag(tag=None):
    stream = models.Journal.select().where(models.Journal.tags.contains(f"{tag}"))
    return render_template('index.html', stream=stream)


# /entries/new - The Create route
# @app.route('/new', methods=('GET', 'POST'))
@app.route('/entries/new', methods=('GET', 'POST'))
@login_required
def Create_Entry():
    form = forms.neform()
    if form.validate_on_submit():
        flash("Yay, you made an entry!", "success")
        #
        models.Journal.add_entry(
        form.Title.data.strip(),
        form.date.data,
        form.Time_Spent.data,
        form.What_You_Learned.data.strip(),
        form.Resources_to_Remember.data.strip(),
        form.tags.data.strip(),
        current_user.username
    )
        return redirect(url_for('index'))
    return render_template('new.html', form=form)


# /entries/<id> - The Detail route
@app.route('/entries/<id>')
def detail(id=None):
    try:
        Detailed_Entry = models.Journal.select().where(models.Journal.entry_id == id)
    except models.DoesNotExist:
        abort(404)
    return render_template('detail.html', entry=Detailed_Entry[0])


# /entries/<id>/edit - The Edit or Update route
@app.route('/entries/<int:id>/edit', methods=('GET', 'POST'))
@login_required
def edit(id=None):
    form = forms.neform()
    try:
        Detailed_Entry = models.Journal.get(models.Journal.entry_id == id)
        if current_user.username != Detailed_Entry.owner and current_user.is_admin == False:
            flash("Updating of other people's entries is not allowed.", 'Success')
            return redirect(url_for('detail', id=Detailed_Entry))
    except models.DoesNotExist:
        abort(404)
    # Fill form
    if form.validate_on_submit():
        # models.Journal.add_entry(
        Detailed_Entry.Title = form.Title.data.strip()
        Detailed_Entry.date = form.date.data
        Detailed_Entry.Time_Spent = form.Time_Spent.data
        Detailed_Entry.What_You_Learned = form.What_You_Learned.data.strip()
        Detailed_Entry.Resources_to_Remember = form.Resources_to_Remember.data.strip()
        Detailed_Entry.tags = form.tags.data.strip()
        Detailed_Entry.save()
        flash('Update successful', 'success')
        # Return to detail page
        return redirect(url_for('detail', id=id))
    else:
        form.Title.data = Detailed_Entry.Title
        form.date.data = Detailed_Entry.date
        form.Time_Spent.data = Detailed_Entry.Time_Spent
        form.What_You_Learned.data = Detailed_Entry.What_You_Learned
        form.Resources_to_Remember.data = Detailed_Entry.Resources_to_Remember
        form.tags.data = Detailed_Entry.tags
    return render_template('edit.html', form=form, id=id)


# /entries/<id>/delete - Delete route
@app.route('/entries/<id>/delete')
@login_required
def delete(id):
    Detailed_Entry = models.Journal.get(models.Journal.entry_id == id)
    if current_user.username != Detailed_Entry.owner and current_user.is_admin == False:
        flash("Deleting of other people's entries is not allowed.", 'Success')
        return redirect(url_for('detail', id=id))
    Detailed_Entry.delete_instance()
    flash('Entry deleted', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    models.initialize()
    models.Journal.add_entry("My muesli", "2021-03-18", 5, "Pineapple", "Healthy.com", "food, fruit", 'Sebastiaan')
    models.Journal.add_entry("My muesli2", "2021-03-28", 5, "Pineapple", "Healthy.com", "food, fruit", 'Someone')
    models.Journal.add_entry("My work", "2021-03-22", 240, "Car\nBikes\nBern", "Drivesafely.com\nWatchOut.com\nGetup.com", "transportation, mobility", 'Sebastiaan')
    try:
        models.User.create_user(
            username='Sebastiaan',
            email='svg35g@gmail.com',
            password='31',
            admin=True
        )
    except ValueError:
        pass

    app.run(threaded=True, use_reloader=False)
