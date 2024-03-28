from flask_cors import CORS
from flask import Flask, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_paginate import get_page_parameter
from flask import jsonify
from flask_admin.contrib.sqla import ModelView
from flask_admin import Admin
from flask_login import LoginManager
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required,decode_token
from flask_jwt_extended.utils import decode_token
from math import ceil

import json


app = Flask(__name__)
CORS(app, origins='http://localhost:3000')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'sWmR0KnnOJTfhtBIv6M9ZcwEoEZa1Ig4'
app.config['JWT_SECRET_KEY'] = 'FpYgPXTgUGK9V6nKOeWbcviMeldqauvT'
jwt = JWTManager(app)

login_manager = LoginManager()
login_manager.init_app(app)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
admin = Admin(app, name='To Do', template_mode='bootstrap3')



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    is_admin = db.Column(db.Boolean, default=False)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    text = db.Column(db.Text)
    email = db.Column(db.Text, nullable=True)
    status = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User', backref='tasks')


class UserView(ModelView):
    column_exclude_list = ('password',)
    
    def on_model_change(self, form, model, is_created):
        if 'password' in form:
            model.password = generate_password_hash(form.password.data)

admin.add_view(UserView(User, db.session, category="Team"))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        data = json.loads(request.data)
        username = data['username']
        password = data['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            access_token = create_access_token(identity=username)
            response = {"access_token":access_token}
            return response
        else:
            return jsonify({'success': False, 'message': 'Invalid username or password'})


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/tasks', methods=['GET', 'POST'])
def tasks():
    page = request.args.get(get_page_parameter(), type=int, default=1)
    per_page = 3
    tasks_pagination = Task.query.paginate(page=page, per_page=per_page, error_out=False)
    total_tasks = tasks_pagination.total
    total_pages = ceil(total_tasks / per_page)
    tasks_list = [{'id': task.id, 'text': task.text, 'email': task.email, 'status': task.status, 'user': task.user.username if task.user else None} for task in tasks_pagination.items]
    return jsonify({'tasks': tasks_list, 'total_pages': total_pages})

@app.route('/create_task', methods=['POST'])
def create_task():
    data = json.loads(request.data)
    jwt_token = request.headers.get('Authorization')
    user = None
    text = data["text"]
    status = bool(int(data["status"]))
    if jwt_token:
        user_id = get_user_from_jwt_token(jwt_token)
        print(user_id)
        user = User.query.filter_by(username=user_id).first()
        print(user)
    new_task = Task(text=text, status=status,user=user)
    db.session.add(new_task)
    db.session.commit()
    total_tasks = Task.query.count()
    per_page = 3
    total_pages = ceil(total_tasks / per_page)
    
    page = request.args.get(get_page_parameter(), type=int, default=1)
    tasks_pagination = Task.query.paginate(page=page, per_page=per_page, error_out=False)
    tasks_list = [{'id': task.id, 'text': task.text, 'email': task.email, 'status': task.status} for task in tasks_pagination.items]
    
    return jsonify({'tasks': tasks_list, 'total_pages': total_pages})


@app.route('/update_task/<int:task_id>',methods=['POST', 'GET'])
@jwt_required()
def update_task(task_id):
    task = Task.query.get(task_id)
    data = json.loads(request.data.decode('utf-8'))
    status = data['status']
    text = data['text']
    if not task:
        return jsonify(({'error': 'Task not found'}), 404)
    status = bool(int(status))
    task.text = text
    task.status = status
    db.session.commit()
    task = {'id': task.id, 'text': task.text, 'email': task.email, 'status': task.status}
    return jsonify({'success': True, 'message': 'Task updated',"task":task})

@app.route('/get_tasks', methods=['GET'])
def get_tasks_by_page():
    page = request.args.get('page', 1, type=int)
    per_page = 3
    tasks_pagination = Task.query.paginate(page=page, per_page=per_page, error_out=False)
    total_tasks = tasks_pagination.total
    total_pages = ceil(total_tasks / per_page)
    tasks_list = [{'id': task.id, 'text': task.text, 'email': task.email, 'status': task.status, 'user': task.user.username if task.user else None} for task in tasks_pagination.items]
    return jsonify({'tasks': tasks_list, 'total_pages': total_pages})

@jwt_required()
def get_user_from_jwt_token(jwt_token):
    token = jwt_token.split()[1]
    decoded_token = decode_token(token)
    user_id = decoded_token.get('sub') 
    return user_id

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True,port=5002)
