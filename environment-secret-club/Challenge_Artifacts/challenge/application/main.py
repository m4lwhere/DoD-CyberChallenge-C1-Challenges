from flask import Flask, request, jsonify, render_template, send_from_directory, send_file, Response
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
import bcrypt
from logging.config import dictConfig
import logging

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})

app = Flask(__name__)
app.config.from_object('application.config.Config')

db = SQLAlchemy(app)
jwt = JWTManager(app)

flag = open("/flag.txt","r").read()

logging.info(f'Admin password is: {app.config["ADMIN_PASSWORD"]}')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(10), default='user')  # Default role is 'user'

    def __repr__(self):
        return f'<User {self.username}>'

class Secret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('secrets', lazy=True))

    def __repr__(self):
        return f'<Secret {self.content}>'


@app.route('/', methods=['GET'])
def home():
        return render_template('index.html')

@app.route('/getname', methods=['GET'])
@jwt_required()
def getname():
    current_user_username = get_jwt_identity()['username']
    user = User.query.filter_by(username=current_user_username).first()

    if not user:
        return jsonify({"msg": "User not found"}), 404
    else:
        return jsonify({'username': current_user_username})


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    data = request.get_json()
    try:

        new_user = User(username=data['username'], 
                        password=bcrypt.hashpw(data['password'].encode(),bcrypt.gensalt()),
                        role='user')
        
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User created successfully.'}), 201
    except:
        return jsonify({'message': 'Error creating user account!'}), 401

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.checkpw(data['password'].encode(),user.password):
        access_token = create_access_token(identity={'username': user.username, 'role': user.role})
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({'message': 'Bad username or password'}), 401

@app.route('/secrets', methods=['GET'])
@jwt_required()
def secret():
    current_user_username = get_jwt_identity()['username']
    user = User.query.filter_by(username=current_user_username).first()

    if not user:
        return jsonify({"msg": "User not found"}), 404

    secrets_query = Secret.query.filter_by(user_id=user.id)
    secrets = [secret.content for secret in secrets_query.all()]

    return jsonify(secrets), 200

@app.route('/add_secret', methods=['POST'])
@jwt_required()
def add_secret():
    current_user_username = get_jwt_identity()['username']
    user = User.query.filter_by(username=current_user_username).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    elif current_user_username == "admin":
        return jsonify({"msg":"This secret store is read-only."}), 403

    data = request.get_json()
    new_secret = Secret(content=data['secret'], user_id=user.id)
    db.session.add(new_secret)
    db.session.commit()

    return jsonify({'message': 'Secret added successfully!'}), 200

@app.route('/.git')
@app.route('/.git/')
def git_route():

    resp = Response(response="\n".join(os.listdir("/app/application/git")),
                    status=200,
                    mimetype="text/plain")
    
    return resp

@app.route('/.git/<path:path>')
def send_git(path):
    return send_from_directory('git', path)

@app.route('/.env')
def send_env():
    return send_file(".env",mimetype="text/plain")

def create_admin_and_secret():
    # Check if the admin user already exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        # Create the admin user
        admin = User(username='admin',
                     password=bcrypt.hashpw(app.config["ADMIN_PASSWORD"].encode(),bcrypt.gensalt()),
                     role='admin')
        
        db.session.add(admin)
        db.session.commit()
    
    # Check if the admin already has the default secret
    admin_secret = Secret.query.filter_by(user_id=admin.id, content=flag).first()
    if not admin_secret:
        # Add a default secret for the admin
        admin_secret = Secret(content=flag, user_id=admin.id)
        db.session.add(admin_secret)
        db.session.commit()

with app.app_context():
    db.create_all()
    create_admin_and_secret()