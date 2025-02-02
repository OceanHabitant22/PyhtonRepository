from wtforms import Form, StringField, TextAreaField, SubmitField, PasswordField, FileField, validators
from wtforms.validators import DataRequired, Email, EqualTo

# Форма для ввода зашифрованных данных
class DataForm(Form):
    name = StringField()
    data_content = TextAreaField('Enter Data to Encrypt', validators=[DataRequired()])
    submit = SubmitField('Submit')

class RegistrationForm(Form):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        EqualTo('confirm', message='Пароли должны совпадать')
    ])
    confirm = PasswordField('Repeat Password')
    submit = SubmitField('Register')

from flask_wtf import FlaskForm

class UploadForm(FlaskForm):
    user_id = StringField('User ID', validators=[DataRequired()])
    file = FileField('Выберите файл', validators=[DataRequired()])
    submit = SubmitField('Загрузить')
