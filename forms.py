from flask_wtf import FlaskForm as Form
from wtforms import StringField, PasswordField, DateField, IntegerField, TextAreaField
from wtforms.validators import (DataRequired, Regexp, ValidationError, Email,
                               Length, EqualTo)

from models import Journal
from models import User

#The register and login code is based on the Treehouse course building a social network with Flask
def name_exists(form, field):
    if User.select().where(User.username == field.data).exists():
        raise ValidationError('User with that name already exists.')


def email_exists(form, field):
    if User.select().where(User.email == field.data).exists():
        raise ValidationError('User with that email already exists.')


class RegisterForm(Form):
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
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])


class neform(Form):
    Title = StringField("Title", validators=[DataRequired()])
    date  = StringField("Date", validators=[DataRequired()])
    Time_Spent = IntegerField("Time spent (hours as int)", validators=[DataRequired()])
    What_You_Learned = TextAreaField("Learned", validators=[DataRequired()])
    Resources_to_Remember = TextAreaField("To Remember", validators=[DataRequired()])
    tags = StringField("tags (as csv)", validators=[DataRequired()])
