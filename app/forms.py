from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, PasswordField, FileField
from wtforms.validators import DataRequired, EqualTo

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Repeat Password')
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class UploadForm(FlaskForm):
    file = FileField('Select File', validators=[DataRequired()])
    submit = SubmitField('Upload')

class DataForm(FlaskForm):
    name = StringField('Name')
    data_content = TextAreaField('Enter Data to Encrypt', validators=[DataRequired()])
    submit = SubmitField('Submit')
