from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError


class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=10)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password',
                             validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    phone_number = StringField('Phone Number',
                               validators=[DataRequired(), Length(min=10, max=10)])
    submit = SubmitField('Register')


"""
    def validate_username(self, username):
        # Check if username is already in db
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists')

    def validate_email(self, email):
        # Check if username is already in db
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already exists')
"""


class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password',
                             validators=[DataRequired()])
    remeber = BooleanField('Remember Me')
    submit = SubmitField('Login')
