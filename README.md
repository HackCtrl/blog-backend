# blog-backend

Backend разработка для сайта Флагманского центра "Руднево"
Обзор проекта
- Нам необходимо разработать backend часть для сайта Флагманского центра "Руднево". Основные задачи:
- Создать систему управления контентом (статьями)
- Реализовать административную панель
- Обеспечить безопасность данных
- Подготовить систему к интеграции с основным сайтом

Распределение задач между тремя разработчиками
*** Разработчик 1: Настройка инфраструктуры и базы данных
Задачи:
- Установка и настройка XAMPP с Apache и PostgreSQL
- Создание структуры базы данных
- Настройка подключения к БД
- Создание базовых моделей данных

Пошаговая инструкция:
Установка XAMPP
- Скачать XAMPP с официального сайта: https://www.apachefriends.org/ru/index.html
- Установить, выбрав компоненты: Apache, PostgreSQL (если доступно) или MySQL
- Запустить панель управления XAMPP и активировать Apache
Установка PostgreSQL (если нет в XAMPP)
- Скачать PostgreSQL: https://www.postgresql.org/download/
- Установить, запомнив пароль для пользователя postgres
- Создать базу данных для проекта: blog_backend
Создание таблиц в PostgreSQL
- Подключиться к БД через pgAdmin или psql
Выполнить SQL-запросы для создания таблиц:

sql
>>>
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE articles (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    image_url VARCHAR(255),
    is_hidden BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
<<<

Настройка подключения к БД
- Создать файл config/database.py:
>>>
import psycopg2
from psycopg2 import OperationalError

def create_connection():
    try:
        connection = psycopg2.connect(
            database="blog_backend",
            user="postgres",
            password="ваш_пароль",
            host="localhost",
            port="5432"
        )
        return connection
    except OperationalError as e:
        print(f"The error '{e}' occurred")
        return None
<<< 

Разработчик 2: Система аутентификации и авторизации
Задачи:
- Реализация регистрации и входа администраторов
- Хеширование паролей
- Защита от SQL-инъекций
- Создание middleware для проверки аутентификации
Пошаговая инструкция:
- Установка зависимостей
- Создать файл requirements.txt:

>>>
flask
flask-sqlalchemy
psycopg2-binary
bcrypt
python-dotenv
<<<
>>>
Реализация хеширования паролей
- Создать файл auth/utils.py:

>>> 
import bcrypt

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode('utf-8'),
        hashed_password.encode('utf-8')
    )
<<< 

Создание моделей пользователя
- Файл models/user.py:

>>> 
from config.database import create_connection

class User:
    @staticmethod
    def create(email: str, username: str, password: str):
        hashed_password = hash_password(password)
        connection = create_connection()
        cursor = connection.cursor()
        
        try:
            cursor.execute(
                "INSERT INTO users (email, username, password) VALUES (%s, %s, %s) RETURNING id",
                (email, username, hashed_password)
            )
            user_id = cursor.fetchone()[0]
            connection.commit()
            return user_id
        except Exception as e:
            connection.rollback()
            raise e
        finally:
            cursor.close()
            connection.close()

    @staticmethod
    def get_by_email(email: str):
        connection = create_connection()
        cursor = connection.cursor()
        
        try:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            return user
        finally:
            cursor.close()
            connection.close()
<<< 

Реализация аутентификации
- Файл auth/auth.py:

>>> 
from flask import jsonify, request
from models.user import User
from auth.utils import verify_password
import jwt
import datetime
from functools import wraps
import os

def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    user = User.get_by_email(email)
    if not user or not verify_password(password, user[3]):
        return jsonify({'message': 'Invalid credentials'}), 401
    
    token = jwt.encode({
        'user_id': user[0],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, os.getenv('SECRET_KEY'), algorithm='HS256')
    
    return jsonify({'token': token})

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 403
        
        try:
            data = jwt.decode(token, os.getenv('SECRET_KEY'), algorithms=['HS256'])
            current_user = User.get_by_id(data['user_id'])
        except:
            return jsonify({'message': 'Token is invalid'}), 403
        
        return f(current_user, *args, **kwargs)
    return decorated
<<<

Разработчик 3: CRUD для статей и админ-панель
Задачи:
- Создание, чтение, обновление и удаление статей
- Реализация админ-панели
- Загрузка изображений
- Защита от XSS-атак
Пошаговая инструкция:
- Модель статьи
- Файл models/article.py:

>>>
from config.database import create_connection
from datetime import datetime

class Article:
    @staticmethod
    def create(title: str, content: str, image_url: str = None):
        connection = create_connection()
        cursor = connection.cursor()
        
        try:
            cursor.execute(
                """INSERT INTO articles (title, content, image_url) 
                VALUES (%s, %s, %s) RETURNING id""",
                (title, content, image_url)
            )
            article_id = cursor.fetchone()[0]
            connection.commit()
            return article_id
        except Exception as e:
            connection.rollback()
            raise e
        finally:
            cursor.close()
            connection.close()

    @staticmethod
    def get_all(include_hidden=False):
        connection = create_connection()
        cursor = connection.cursor()
        
        try:
            if include_hidden:
                cursor.execute("SELECT * FROM articles ORDER BY created_at DESC")
            else:
                cursor.execute("SELECT * FROM articles WHERE is_hidden = FALSE ORDER BY created_at DESC")
            return cursor.fetchall()
        finally:
            cursor.close()
            connection.close()

    @staticmethod
    def update(article_id: int, title: str, content: str, image_url: str = None):
        connection = create_connection()
        cursor = connection.cursor()
        
        try:
            cursor.execute(
                """UPDATE articles 
                SET title = %s, content = %s, image_url = %s, updated_at = %s 
                WHERE id = %s""",
                (title, content, image_url, datetime.now(), article_id)
            )
            connection.commit()
        except Exception as e:
            connection.rollback()
            raise e
        finally:
            cursor.close()
            connection.close()

    @staticmethod
    def toggle_visibility(article_id: int):
        connection = create_connection()
        cursor = connection.cursor()
        
        try:
            cursor.execute(
                """UPDATE articles 
                SET is_hidden = NOT is_hidden, updated_at = %s 
                WHERE id = %s""",
                (datetime.now(), article_id)
            )
            connection.commit()
        except Exception as e:
            connection.rollback()
            raise e
        finally:
            cursor.close()
            connection.close()

    @staticmethod
    def delete(article_id: int):
        connection = create_connection()
        cursor = connection.cursor()
        
        try:
            cursor.execute("DELETE FROM articles WHERE id = %s", (article_id,))
            connection.commit()
        except Exception as e:
            connection.rollback()
            raise e
        finally:
            cursor.close()
            connection.close()
<<< 

Контроллеры для статей
- Файл controllers/article_controller.py:

>>> 
from flask import jsonify, request
from models.article import Article
from auth.auth import token_required
import bleach

def init_article_routes(app):
    @app.route('/api/articles', methods=['GET'])
    def get_articles():
        articles = Article.get_all()
        return jsonify([{
            'id': article[0],
            'title': article[1],
            'content': article[2],
            'image_url': article[3],
            'created_at': article[5]
        } for article in articles])

    @app.route('/api/articles', methods=['POST'])
    @token_required
    def create_article(current_user):
        data = request.get_json()
        
        # Очистка от потенциальных XSS-атак
        title = bleach.clean(data.get('title'))
        content = bleach.clean(data.get('content'))
        image_url = data.get('image_url')
        
        article_id = Article.create(title, content, image_url)
        return jsonify({'message': 'Article created', 'id': article_id}), 201

    @app.route('/api/articles/<int:article_id>', methods=['PUT'])
    @token_required
    def update_article(current_user, article_id):
        data = request.get_json()
        
        title = bleach.clean(data.get('title'))
        content = bleach.clean(data.get('content'))
        image_url = data.get('image_url')
        
        Article.update(article_id, title, content, image_url)
        return jsonify({'message': 'Article updated'})

    @app.route('/api/articles/<int:article_id>/toggle', methods=['PUT'])
    @token_required
    def toggle_article(current_user, article_id):
        Article.toggle_visibility(article_id)
        return jsonify({'message': 'Article visibility toggled'})

    @app.route('/api/articles/<int:article_id>', methods=['DELETE'])
    @token_required
    def delete_article(current_user, article_id):
        Article.delete(article_id)
        return jsonify({'message': 'Article deleted'})
<<< 

Загрузка изображений
- Файл utils/file_upload.py:

>>> 
import os
from werkzeug.utils import secure_filename
from flask import current_app

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_uploaded_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        upload_folder = current_app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        filepath = os.path.join(upload_folder, filename)
        file.save(filepath)
        return filename
    return None
<<<

Интеграция всех компонентов
- Создание основного приложения
Файл app.py:

>>> 
from flask import Flask
from config.database import create_connection
from auth.auth import login
from controllers.article_controller import init_article_routes
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = 'uploads'

# Инициализация маршрутов
app.route('/api/login', methods=['POST'])(login)
init_article_routes(app)

if __name__ == '__main__':
    # Проверка подключения к БД
    conn = create_connection()
    if conn:
        print("Successfully connected to the database")
        conn.close()
    else:
        print("Failed to connect to the database")
    
    app.run(debug=True)
<<, 
Создание файла окружения
- Файл .env:

>>> 
SECRET_KEY=ваш_секретный_ключ
DATABASE_URL=postgresql://postgres:ваш_пароль@localhost:5432/blog_backend
<<<

Инструкция по совместной работе в Git
- Настройка репозитория
- Клонировать существующий репозиторий:

>>> git clone https://github.com/ваш-аккаунт/blog-backend.git
>>> cd blog-backend
>>> 
Создание веток для каждого разработчика
- Разработчик 1 (инфраструктура):
>>> git checkout -b feature/database-setup

- Разработчик 2 (аутентификация):
>>> git checkout -b feature/auth-system

- Разработчик 3 (статьи и админка):
>>> git checkout -b feature/article-crud

Работа над своими задачами
- Каждый разработчик работает в своей ветке
- Регулярные коммиты с понятными сообщениями:

Слияние изменений
- После завершения каждой задачи:
>>> git checkout main
>>> git pull origin main
>>> git merge feature/название-ветки
>>> git push origin main
>>> Решение возможных конфликтов

Тестирование
- После слияния всех веток провести комплексное тестирование:
- Проверка регистрации и входа
- Проверка CRUD операций со статьями
- Проверка безопасности (попытки SQL-инъекций, XSS)
Деплой и интеграция с основным проектом
- Подготовка к деплою
- Создать файл requirements.txt со всеми зависимостями
- Настроить конфигурацию для production (отключить debug режим)
- Интеграция с фронтендом
- Предоставить API endpoints для фронтенд-разработчиков:

>>> /api/login - POST для аутентификации
>>> /api/articles - GET/POST для получения и создания статей
>>> /api/articles/<id> - PUT/DELETE для обновления и удаления
>>> /api/articles/<id>/toggle - PUT для скрытия/показа

Документация API
- Создать файл API_DOCUMENTATION.md с описанием всех endpoints

Заключение
- После выполнения всех шагов у нас будет:
- Рабочая backend система для управления контентом
- Безопасная система аутентификации администраторов
- Админ-панель для управления статьями
- Готовое к интеграции API
