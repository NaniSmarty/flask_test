import pymongo
from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
import random

app = Flask(__name__)
# app.config['MONGO_URI'] = 'mongodb://Aryan:root%40123@192.168.10.134:27017/?authMechanism=DEFAULT&authSource=test'  # Replace with your MongoDB connection URI
app.config['JWT_SECRET_KEY'] = 'narayanarajugitech13*gitech'  # Replace with your secret key
# mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
# client = MongoClient('mongodb://Aryan:root%40123@192.168.10.134:27017/?authMechanism=DEFAULT')
# client = MongoClient("mongodb://<narayanraju>:<narayanraju220797>@0.0.0.0/<test>")
client = MongoClient("mongodb+srv://narayanraju:<narayanraju220797>@cluster0.fiudarr.mongodb.net/")


def get_next_sequence(collection, name):
    counter = collection.find_one_and_update(
        {'_id': name},
        {'$inc': {'sequence_value': 1}},
        upsert=True,
        return_document=True
    )
    return counter['sequence_value']

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    firstname = data.get('firstname')
    lastname = data.get('lastname')
    email = data.get('email')
    password = data.get('password')

    # Check if the user already exists
    # if mongo.db.users.find_one({'username': username}):
    #     return jsonify({'message': 'User already exists'}), 400
    if client['test']['users'].find_one({'email': email}):
        return jsonify({'message': 'User already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    client['test']['users'].insert_one({'firstname': firstname, 'lastname': lastname, 'email': email, 'password': hashed_password})
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = client['test']['users'].find_one({'email': email})

    if user and bcrypt.check_password_hash(user['password'], password):
        access_token = create_access_token(identity=email)
        return jsonify({'access_token': access_token}), 200

    return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({'message': f'You are logged in as {current_user}'}), 200


# Create an item
@app.route('/template', methods=['POST'])
# @jwt_required()
def create_item():
    data = request.get_json()
    template_name = data.get('template_name')
    subject = data.get('subject')
    body = data.get('body')
    order_number = get_next_sequence(client['test']['template'], 'template_id')
    if "body" not in data:
        return jsonify({"error": "Body is required"}), 400
    item_id = client['test']['template'].insert_one({'template_id': order_number, 'template_name': template_name, 'subject': subject, 'body': body})
    return jsonify({"message": "Template created"}), 201

# Read all items
@app.route('/template', methods=['GET'])
@jwt_required()
def get_items():
    items = list(client['test']['template'].find({}, {'_id': False}))
    return jsonify(items), 200

# Read a specific item
@app.route('/template/<template_id>', methods=['GET'])
@jwt_required()
def get_item(template_id):
    item = client['test']['template'].find_one({'template_id': int(template_id)}, {'_id': False})
    if item:
        return jsonify(item), 200
    return jsonify({"error": "Item not found"}), 404

# Update an item
@app.route('/template/<template_id>', methods=['PUT'])
@jwt_required()
def update_item(template_id):
    data = request.get_json()
    result = client['test']['template'].update_one({'template_id': int(template_id)}, {'$set': data})
    if result.modified_count > 0:
        return jsonify({"message": "Template updated"}), 200
    return jsonify({"error": "Template not found"}), 404

# Delete an item
@app.route('/template/<template_id>', methods=['DELETE'])
@jwt_required()
def delete_item(template_id):
    result = client['test']['template'].delete_one({'template_id': int(template_id)})
    if result.deleted_count > 0:
        return jsonify({"message": "Template deleted"}), 200
    return jsonify({"error": "Template not found"}), 404


if __name__ == '__main__':
    app.run(debug=True)





