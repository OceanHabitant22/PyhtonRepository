from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, PasswordField, FileField, Form, validators
from wtforms.validators import DataRequired, Email, EqualTo

# Форма для ввода зашифрованных данных
class DataForm(FlaskForm):
    name = StringField()
    data_content = TextAreaField('Enter Data to Encrypt', validators=[DataRequired()])
    submit = SubmitField('Submit')
class RegistrationForm(FlaskForm):  # Наследование от FlaskForm вместо Form
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        EqualTo('confirm', message='Пароли должны совпадать')
    ])
    confirm = PasswordField('Repeat Password')
    submit = SubmitField('Register')
class UploadForm(FlaskForm):
    file = FileField('File', validators=[DataRequired()])
    submit = SubmitField('Upload')