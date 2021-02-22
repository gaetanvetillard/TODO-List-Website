from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from wtforms.fields.html5 import DateField

class LoginForm(FlaskForm):
    email = StringField("* Email Adress", validators=[DataRequired()])
    password = PasswordField("* Password", validators=[DataRequired()])
    submit = SubmitField("Log In")

class RegisterForm(FlaskForm):
    username = StringField("* Username", validators=[DataRequired()])
    email = StringField("* Email Adress", validators=[DataRequired()])
    password = PasswordField("* Password", validators=[DataRequired()])
    submit = SubmitField("Sign In")