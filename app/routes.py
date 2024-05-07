from flask import jsonify, request, current_app as app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from app import app, db
from app.models import User

@app.route('/hellotest', methods=['GET'])
def hellotest():
    return jsonify({'message': 'Hello!'})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists'}), 400

    user = User(name=name, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    access_token = create_access_token(identity={'id': user.id, 'name': user.name})
    return jsonify(access_token=access_token), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        access_token = create_access_token(identity={'id': user.id, 'name': user.name})
        return jsonify(access_token=access_token), 200

    return jsonify({'message': 'Invalid email or password'}), 401

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200
