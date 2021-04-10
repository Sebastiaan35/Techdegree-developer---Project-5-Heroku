#!/usr/bin/env python3
"""The forms part"""

from flask_wtf import FlaskForm as Form
from wtforms import (StringField, PasswordField, IntegerField, TextAreaField,
                     DateField, BooleanField)
from wtforms.validators import (DataRequired, Regexp, ValidationError, Email,
                                Length, EqualTo)

from models import User


# The register and login code is based on the Treehouse course
# Building a social network with Flask
def name_exists(form, field):
    """Check if username already in database"""
    if User.select().where(User.username == field.data).exists():
        raise ValidationError('User with that name already exists.')


def email_exists(form, field):
    """Check if email address already in database"""
    if User.select().where(User.email == field.data).exists():
        raise ValidationError('User with that email already exists.')


class RegisterForm(Form):
    """The registration form"""
    username = StringField(
        'Username',
        validators=[
            DataRequired(),
            Regexp(
                r'^[a-zA-Z0-9_]+$',
                message=("Username should be one word, letters, "
                         "numbers, and underscores only.")
            ),
            name_exists
        ])
    email = StringField(
        'Email',
        validators=[
            DataRequired(),
            Email(),
            email_exists
        ])
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=2),
            EqualTo('password2', message='Passwords must match')
        ])
    password2 = PasswordField(
        'Confirm Password',
        validators=[DataRequired()]
    )


class LoginForm(Form):
    """The login form"""
    email = StringField('Email', validators=[DataRequired(
        message='Please fill in an email address.'), Email(
        message='This is not a valid email address.')])
    password = PasswordField('Password', validators=[DataRequired(
        message='Please fill in a password.')])


class NewForm(Form):
    """New entry form"""
    title = StringField("Title", validators=[DataRequired()])
    date = DateField("Date (dd.mm.yyyy)", format='%d.%m.%Y',
                     validators=[DataRequired()])
    time_spent = IntegerField("Time spent (hours as a whole number)",
                              validators=[DataRequired()])
    Characters = TextAreaField("Characters", validators=[DataRequired()])
    Play = TextAreaField(
        "Play",
        validators=[DataRequired()])
    tags = StringField("Keywords - Separated by ', ' (comma and space)",
                       validators=[DataRequired()])


class AdminForm(Form):
    admin = BooleanField()
