from wtforms import Form, TextField, PasswordField
from wtforms.validators import required

__author__ = 'yoophi'


class LoginForm(Form):
    username = TextField('Username', [required()])
    password = PasswordField('Password', [required()])