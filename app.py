from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
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
    
    user = User.query.filter_by(username=username).first()
    
    if not user or user.password != password:
        return jsonify({"message": "Invalid credentials"}), 400

    login_user(user)

    return jsonify({"id": user.id, "username": username})

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
    
    user = User.query.filter_by(username=username).first()
    
    if user:
        return jsonify({"message": "Invalid data"}), 400
    
    new_user = User(username=username, password=password)
    db.session.add(new_user)
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

    if not user:
        return jsonify({"message": f"User [{user_id}] not fount"}), 404

    if data.get("password"):
        user.password = data.get("password")
        db.session.commit()

    return jsonify(user.to_dict())

@app.route('/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    user = db.session.get(User, user_id)

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
