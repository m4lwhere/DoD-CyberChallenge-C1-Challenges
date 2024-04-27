from flask import Flask, request, jsonify, make_response, render_template, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
import os

app = Flask("app")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ctf.db'
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)  # In a real app, ensure passwords are hashed
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
        new_user = User(username=data['username'], password=data['password'], role='user')
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
    if user and user.password == data['password']:  # In a real app, use hashed passwords
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

    data = request.get_json()
    new_secret = Secret(content=data['secret'], user_id=user.id)
    db.session.add(new_secret)
    db.session.commit()

    return jsonify({'message': 'Secret added successfully!'}), 200

def create_admin_and_secret():
    # Check if the admin user already exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        # Create the admin user
        password = os.urandom(16).hex()
        admin = User(username='admin', password=password, role='admin')
        print(f'Admin password is: {password}')
        db.session.add(admin)
        db.session.commit()
    
    # Check if the admin already has the default secret
    admin_secret_content = os.getenv('FLAG')
    admin_secret = Secret.query.filter_by(user_id=admin.id, content=admin_secret_content).first()
    if not admin_secret:
        # Add a default secret for the admin
        admin_secret = Secret(content=admin_secret_content, user_id=admin.id)
        db.session.add(admin_secret)
        db.session.commit()

with app.app_context():
    db.create_all()
    create_admin_and_secret()

if __name__ == '__main__':
    app.run(debug=True)