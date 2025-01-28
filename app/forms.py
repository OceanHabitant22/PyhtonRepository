from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, PasswordField, FileField
from wtforms.validators import DataRequired, Email

# Форма для ввода зашифрованных данных
class DataForm(FlaskForm):
    data_content = TextAreaField('Enter Data to Encrypt', validators=[DataRequired()])
    submit = SubmitField('Submit')
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
class UploadForm(FlaskForm):
    user_id = StringField('User ID', validators=[DataRequired()])
    file = FileField('Выберите файл', validators=[DataRequired()])
    submit = SubmitField('Загрузить')