from flask import Blueprint, render_template

# Создаем объект Blueprint
main = Blueprint('main', __name__)

# Определяем маршрут для главной страницы
@main.route('/')
def index():
    return render_template('index.html')
