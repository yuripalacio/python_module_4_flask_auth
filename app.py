from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required

import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/flask-crud'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not(username and password):
        return jsonify({"message": "Invalid credentials"}), 400
    
    user_exists = User.query.filter_by(username=username).first()
    
    if not user_exists or not bcrypt.checkpw(str.encode(password), str.encode(user_exists.password)):
        return jsonify({"message": "Invalid credentials"}), 400

    login_user(user_exists)

    return jsonify({"id": user_exists.id, "username": username})

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout successfully"})
    return "Hello world"

@app.route('/users', methods=['POST'])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not(username and password):
        return jsonify({"message": "Invalid data"}), 400
    
    user_exists = User.query.filter_by(username=username).first()
    
    if user_exists:
        return jsonify({"message": "Invalid data"}), 400
    
    hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
    user = User(username=username, password=hashed_password, role='user')
    db.session.add(user)
    db.session.commit()
    
    return jsonify({"message": "User registered successfully"})

@app.route('/users/<int:user_id>', methods=['GET'])
@login_required
def read_user(user_id):
    user = db.session.get(User, user_id)

    if not user:
        return jsonify({"message": f"User [{user_id}] not fount"}), 404
    
    return jsonify(user.to_dict())

@app.route('/users/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    data = request.json
    user = db.session.get(User, user_id)
    field_updated = False

    if not user:
        return jsonify({"message": f"User [{user_id}] not fount"}), 404
    
    if data.get("role") and current_user.role != 'admin':
        return jsonify({"message": "Action not allowed"}), 403

    if data.get("password"):
        hashed_password = bcrypt.hashpw(str.encode(data.get("password")), bcrypt.gensalt())
        user.password = hashed_password
        field_updated = True

    if data.get("role"):
        user.role = data.get("role")
        field_updated = True

    if field_updated:
        db.session.commit()

    return jsonify(user.to_dict())

@app.route('/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    user = db.session.get(User, user_id)

    if current_user.role != 'admin':
        return jsonify({"message": "Action not allowed"}), 403

    if not user:
        return jsonify({"message": f"User [{user_id}] not fount"}), 404
    
    if user.username == 'admin':
        return jsonify({"message": "Invalid data"}), 400

    db.session.delete(user)
    db.session.commit()

    if user_id == current_user.id:
        logout_user()
    
    return jsonify({"message": "User deleted successfully"})

if __name__ == '__main__':
    app.run(debug=True)
