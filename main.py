import os
import boto3
import certifi
from flask_pymongo import PyMongo
from flask_restful import Resource, Api
from pymongo import MongoClient
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask import Flask, Response, jsonify, request, make_response, render_template, flash, redirect, g, after_this_request, json, abort
from bson.json_util import dumps
from bson.objectid import ObjectId
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from botocore.exceptions import NoCredentialsError
from bson import ObjectId, json_util
from flask_basicauth import BasicAuth
from flask_bcrypt import Bcrypt
import ssl
from datetime import datetime, timedelta

app = Flask(__name__)

jwt = JWTManager(app)
cors = CORS(app)
bcrypt = Bcrypt(app)
auth = HTTPBasicAuth()
app.config["CORS_HEADERS"] = "Content-Type"

# # Specify the path to your downloaded self-signed certificate file
# certfile = '/private/etc/ssl/cert.pem'

# # Create an SSL context with CERT_NONE
# ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
# ssl_context.load_cert_chain(certfile)

# # Disable SSL certificate verification at the SSL context level
# ssl_context.verify_mode = ssl.CERT_NONE
# ssl=True, ssl_context=ssl_context, 

# mongodb+srv://pratyush:<replace-with-your-password>@superminds-cluster-7f2d92d1.mongo.ondigitalocean.com/tapzzi?tls=true&authSource=admin&replicaSet=superminds-cluster
connection_string = f"mongodb+srv://pratyush:43O86u20v1HPDL9h@superminds-cluster-7f2d92d1.mongo.ondigitalocean.com/fortywinks?tls=true&ssl=true&authSource=admin&replicaSet=superminds-cluster" 
client = MongoClient(connection_string,tlsCAFile=certifi.where())
app.config['MONGO_URI'] = "mongodb+srv://pratyush:43O86u20v1HPDL9h@superminds-cluster-7f2d92d1.mongo.ondigitalocean.com/fortywinks?tls=true&ssl=true&authSource=admin&replicaSet=superminds-cluster"
mongo = PyMongo(app)

db = client['fortywinks'] 
collection1 = db['profiles']
files_collection = db['files']
users_collection = db['users']
notifications_collection = db['notifications']
devices_collection = db['devices']
contacts_collection = db['contacts']
reports_collection = db['reports']
supportrequests_collection = db['supportrequests']
subscriptions_collection = db['subscriptions']
sessions_collection = db['sessions'] 

auth = HTTPBasicAuth()
basic_auth = BasicAuth(app)
api = Api(app)

SWAGGER_URL = '/swagger'  # URL for exposing Swagger UI (without trailing '/')
API_URL = '/static/swagger.json'  # Our API url (can of course be a local resource)

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,  # Swagger UI static files will be mapped to '{SWAGGER_URL}/dist/'
    API_URL,
    config={ 
        'app_name': "FortyWinks",
        'uiversion': 3,
        'supportedSubmitMethods': ['get', 'post', 'put', 'delete'],
        'securityDefinitions': {
            'basicAuth': {
                'type': 'basic',
                'description': 'Basic HTTP Authentication',
            },
        },
        'security': [{'basicAuth': []}],
    },
)

app.register_blueprint(swaggerui_blueprint, url_prefix = SWAGGER_URL)

@app.route('/static/swagger.json')
@auth.login_required
def send_swagger_json():
    return app.send_static_file('swagger.json')

# Configure JWT
app.config['JWT_SECRET_KEY'] = '854d9f0a3a754b16a6e1f3655b3cfbb5'
jwt = JWTManager(app)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['PROPAGATE_EXCEPTIONS'] = True

headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcwMDQ3MTg0NCwianRpIjoiNjg1MDdkZDAtOGZiYS00NTM1LTk0M2UtODE3MDcwODMyODM2IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6InVzZXIxIiwibmJmIjoxNzAwNDcxODQ0LCJleHAiOjE3MDA0NzI3NDR9.LwwPvBpOwU6xi6pGAEMUo7KkzFfAZ4S_VYPLrS90k_k'
}

@app.route('/signup', methods=['POST'])
def register_user():
    data = request.get_json()

    if 'username' not in data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Username, password and email are required'}), 400

    username = data['username']
    password = data['password']
    email = data['email']

    existing_user = users_collection.find_one({'username': username})
    if existing_user:
        return jsonify({'error': 'Username already exists'}), 409

    existing_email = users_collection.find_one({'email': email})
    if existing_email:
        return jsonify({'error': 'Email already exists'}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    users_collection.insert_one({
        'username': username,
        'email' : email,
        'password': hashed_password
    })

    return jsonify({'message': 'User registered successfully'}), 201

@auth.verify_password
def verify_password(username, password):
    print(f"Received username: {username}, password: {password}")
    user = users_collection.find_one({'username': username})
    if user and bcrypt.check_password_hash(user['password'], password):
        return username
    if user:
        stored_password = user.get('password')
        print(f"Stored password: {stored_password}")
        if bcrypt.check_password_hash(stored_password, password):
            print("Authentication successful")
            return username

    print("Authentication failed")
    return False

@app.route('/')
@auth.login_required
def index():
    return "Hello, {}!".format(auth.current_user())

unique_session_id = str(ObjectId())

# Token creation route (login)
@app.route('/login', methods=['GET','POST'])
def login():
    data = request.get_json()
    username = data.get('username', None)
    password = data.get('password', None)

    user = users_collection.find_one({'username': username})

    if user and user['password'] == password:
        access_token = create_access_token(identity=username)

        new_session = {
            '_id': unique_session_id,  # Assuming user['_id'] is the MongoDB ObjectId
            'is_active': True,
            'timestamp': datetime.utcnow()
        }
        sessions_collection.insert_one(new_session)

        return jsonify(access_token=access_token), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

class UserResource(Resource):
    def delete(self, user_id):
        # Convert the user_id string to ObjectId
        user_id_object = ObjectId(user_id)

        # Check if the user exists
        user = users_collection.find_one({'_id': user_id_object})

        if user:
            # Delete the user
            users_collection.delete_one({'_id': user_id_object})
            return jsonify({'message': 'User loggedout successfully'})

        # If user does not exist, return a JSON response with a 404 status code
        return make_response(jsonify({'message': 'User not found'}), 404)

api.add_resource(UserResource, '/user/<string:user_id>')

class ChangePasswordResource(Resource):
    @jwt_required()
    def put(self, user_id):
        data = request.get_json()

        # Retrieve user from MongoDB
        user = users_collection.find_one({'_id': ObjectId(user_id)})

        if user:
            old_password = data.get('old_password')
            new_password = data.get('new_password')
            confirm_password = data.get('confirm_password')

            # Validate old password
            if old_password != user['password']:
                return {'message': 'Invalid old password'}, 401

            # Validate new password and confirm password
            if new_password != confirm_password:
                return {'message': 'New password and confirm password do not match'}, 400

            # Update the password in the database
            users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': {'password': new_password}})

            return {'message': 'Password changed successfully'}, 200

        return {'message': 'User not found'}, 404

api.add_resource(ChangePasswordResource, '/change-password/<string:user_id>')

class DevicesResource(Resource):
    @jwt_required()
    def get(self):
        # Retrieve the list of logged-in devices
        devices = devices_collection.find()
        devices_list = [{'_id': str(device['_id']), 'device_name': device['device_name']} for device in devices]

        return {'devices': devices_list}, 200

    def post(self):
        data = request.get_json()

        # Validate required fields
        if 'device_name' not in data:
            return {'message': 'Device name is required'}, 400

        # Add the new device to the list of logged-in devices
        device_id = devices_collection.insert_one({'device_name': data['device_name']}).inserted_id

        return {'message': 'Device logged in successfully', 'device_id': str(device_id)}, 201

class LogoutResource(Resource):
    @jwt_required()
    def delete(self, device_id):
        # Check if the device exists
        device = devices_collection.find_one({'_id': ObjectId(device_id)})

        if device:
            # Remove the device from the list of logged-in devices
            devices_collection.delete_one({'_id': ObjectId(device_id)})
            return {'message': 'Device logged out successfully'}, 200

        return {'message': 'Device not found'}, 404

api.add_resource(DevicesResource, '/devices')
api.add_resource(LogoutResource, '/devices/logout/<string:device_id>')


from flask_mail import Mail, Message
import random
import string
import pyotp
from datetime import datetime, timedelta

app.config['MAIL_SERVER'] = 'smtp.dreamhost.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'no-reply@oemails.net'
app.config['MAIL_PASSWORD'] = 'x006Ar4tyBil956P'

mail = Mail(app)

class ResetPasswordResource(Resource):
    def post(self):
        data = request.get_json()

        # Validate required fields
        if 'email' not in data:
            return {'message': 'Email is required'}, 400

        # Check if the email exists in the database
        user = users_collection.find_one({'email': data['email']})

        if user:
            # Generate a random 6-digit OTP
            otp = ''.join(random.choices(string.digits, k=6))

            # Save the OTP in the database (you might want to encrypt it in production)
            users_collection.update_one({'_id': user['_id']}, {'$set': {'otp': otp}})

            # Send OTP via email
            msg = Message('Password Reset OTP', sender='no-reply@oemails.net', recipients=[data['email']])
            msg.body = f'Your OTP for password reset is: {otp}'
            mail.send(msg)

            return {'message': 'OTP sent successfully'}, 200

        return {'message': 'Email not found'}, 404

class VerifyOTPRemote(Resource):
    def post(self):
        data = request.get_json()

        # Validate required fields
        if 'email' not in data or 'otp' not in data:
            return {'message': 'Email and OTP are required'}, 400

        # Check if the email exists in the database
        user = users_collection.find_one({'email': data['email']})

        if user and 'otp' in user and user['otp'] == data['otp']:
            # If OTP is valid, return success message
            return {'message': 'OTP verified successfully'}, 200

        return {'message': 'Invalid OTP or email not found'}, 401

class ResetPasswordRemote(Resource):
    def post(self):
        data = request.get_json()

        # Validate required fields
        if 'email' not in data or 'new_password' not in data:
            return {'message': 'Email and new password are required'}, 400

        # Check if the email exists in the database
        user = users_collection.find_one({'email': data['email']})

        if user:
            # Update the password in the database
            users_collection.update_one({'_id': user['_id']}, {'$set': {'password': data['new_password']}})

            # Clear the OTP in the database after password reset
            users_collection.update_one({'_id': user['_id']}, {'$unset': {'otp': ''}})

            return {'message': 'Password reset successfully'}, 200

        return {'message': 'Email not found'}, 404

api.add_resource(ResetPasswordResource, '/reset-password')
api.add_resource(VerifyOTPRemote, '/verify-otp')
api.add_resource(ResetPasswordRemote, '/reset-password-remote')

# # Configure Flask-Mail
# app.config['MAIL_SERVER'] = 'smtp.example.com'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = 'pratyush@superminds.dev'
# app.config['MAIL_PASSWORD'] = 'Popeye#9'
# mail = Mail(app)

# otp_secret = pyotp.random_base32()

# # Helper function to send OTP via email
# def send_otp_email(email, otp):
#     msg = Message('Password Reset OTP', sender='pratyush@superminds.dev', recipients=[email])
#     msg.body = f'Your OTP for password reset is: {otp}'
#     mail.send(msg)

# # API endpoint for requesting a password reset
# @app.route('/reset-password', methods=['POST'])
# def request_reset_password():
#     data = request.get_json()
#     email = data.get('email')

#     # Check if the email exists in the database
#     user = users_collection.find_one({'email': email})
#     if user:
#         # Generate OTP and store it in the database with a timestamp
#         otp = pyotp.TOTP(otp_secret).now()
#         expiration_time = datetime.utcnow() + timedelta(minutes=10)
#         mongo.db.reset_tokens.update_one({'email': email}, {'$set': {'otp': otp, 'expiration_time': expiration_time}}, upsert=True)

#         # Send OTP via email
#         send_otp_email(email, otp)

#         return jsonify({'message': 'OTP sent successfully'})

#     return jsonify({'message': 'Email not found'}), 404

# # # API endpoint for verifying the OTP and resetting the password
# @app.route('/reset-password/verify', methods=['POST'])
# def verify_reset_password():
#     data = request.get_json()
#     email = data.get('email')
#     otp = data.get('otp')
#     new_password = data.get('new_password')

#     # Check if the email and OTP combination is valid
#     reset_token = mongo.db.reset_tokens.find_one({'email': email, 'otp': otp, 'expiration_time': {'$gt': datetime.utcnow()}})
#     if reset_token:
#         # Update the user's password in the database
#         users_collection.update_one({'email': email}, {'$set': {'password': new_password}})

#         # Remove the reset token from the database
#         mongo.db.reset_tokens.delete_one({'email': email})

#         return jsonify({'message': 'Password reset successful'})

#     return jsonify({'message': 'Invalid or expired OTP'}), 401

validation_rules = {
    "fullname": "required",
    "imageUrl": "required",
    "email": "required",
    "dob": "required",
    "phonenumber": "required",
    "country": "required",
    "theme": "optional"
    }

# Create a profile
@app.route('/profile', methods=['POST'])
def create_profile():
    data = request.get_json()
    # Perform your validations
    validation_errors = validate_data(data, validation_rules)

    if validation_errors:
        # If there are validation errors, send a response with the errors
        return jsonify({"errors": validation_errors}), 400

    inserted_id = collection1.insert_one(data).inserted_id

    # If validation passes, create a response with the desired data
    response_data = {
        "fullname": data.get("fullname"),
        "imageUrl": data.get("imageUrl"),
        "email": data.get("email"),
        "dob": data.get("dob"),
        "phonenumber": data.get("phonenumber"),
        "country": data.get("country"),
        'theme': 'light',
        "_id": str(inserted_id)
        # Add more fields as needed
    }

    return jsonify(response_data)

def validate_data(data, validation_rules):
    errors = []

    for field, rule in validation_rules.items():
        if rule == "required" and not data.get(field):
            errors.append(f"{field} is required.")
        elif rule == "optional" and field in data and not data.get(field):
            errors.append(f"{field} must be optional.")

    return errors

# Update a profile
@app.route('/profile/<id>', methods=['PUT'])
@jwt_required()
def update_profile(id):
    id = ObjectId(id)
    data = request.get_json()
    validation_errors = validate_data(data, validation_rules)

    if validation_errors:
        return jsonify({"errors": validation_errors}), 400
    
    existing_document = collection1.find_one({"_id": id})

    if existing_document is None:
        return jsonify({"error": "Profile not found"}), 404

    result = collection1.update_one({"_id": ObjectId(id)}, {"$set": data})

    response_data = {
        "fullname": data.get("fullname"),
        "imageUrl": data.get("imageUrl"),
        "email": data.get("email"),
        "dob": data.get("dob"),
        "phonenumber": data.get("phonenumber"),
        "country": data.get("country"),
        "_id": str(id)
        # Add more fields as needed
    }

    if result.matched_count == 0:
        return jsonify({"error": "Profile not found"}), 404
    elif result.modified_count == 0:
        return jsonify({"error": "Profile not updated"}), 404
    else:
        return jsonify(response_data)

# Get all profiles
@app.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    profiles = list(collection1.find())
    data = []
    for profile in profiles:
        profile['_id'] = str(profile['_id'])
        data.append(profile)
    return jsonify(data)

# Get a specific profile by ID
@app.route('/profile/<id>')
@jwt_required()
def profile(id):
    profile = collection1.find_one({'_id':ObjectId(id)})
    if profile:
        profile["_id"] = str(profile["_id"])
        return profile
    else:
        return jsonify({"error": "Profile Not Found"}), 404

# Delete a profile
@app.route('/profile/<id>', methods=['DELETE'])
@jwt_required()
def delete_profile(id):
    id = ObjectId(id)
    result = collection1.delete_one({"_id": ObjectId(id)})
    if result.deleted_count > 0:
        return jsonify({"message": "Profile deleted successfully"})
    else:
        return jsonify({"error": "Profile not found or not deleted"}), 404

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE_BYTES = 500 * 500 #10 * 1024 * 1024
DO_SPACES_ENDPOINT = 'https://fortywinks.blr1.digitaloceanspaces.com'  # Replace with your Space URL
DO_ACCESS_KEY = 'DO00FVYZELDGLP9XU3Y4'  # Replace with your DigitalOcean Spaces access key
DO_SECRET_KEY = '3SuOMJtlfNklPrhwv9U3FmkgnhVXbKU+u3fGG1zaZ/g'  # Replace with your DigitalOcean Spaces secret key
DO_BUCKET_NAME = 'fortywinks'  # Replace with your DigitalOcean Spaces bucket name

# Create a connection to DigitalOcean Spaces
# s3 = boto3.client('s3', endpoint_url=DO_SPACES_ENDPOINT, aws_access_key_id=DO_ACCESS_KEY, aws_secret_access_key=DO_SECRET_KEY)

def allowed_file_size(file):
    return file.content_length <= MAX_FILE_SIZE_BYTES

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_to_digitalocean(file, file_name, device_type, profile_id):
    try:
        s3 = boto3.client('s3',
            aws_access_key_id='DO00FVYZELDGLP9XU3Y4',
            aws_secret_access_key='3SuOMJtlfNklPrhwv9U3FmkgnhVXbKU+u3fGG1zaZ/g',
            endpoint_url=DO_SPACES_ENDPOINT
        )

        # Create a folder with the specified device type
        folder_path = f"{device_type}/"
        file_path = os.path.join(folder_path, file_name)

        # Upload the file to DigitalOcean Spaces
        s3.upload_fileobj(file, DO_BUCKET_NAME, file_path)

        # Get the public URL of the uploaded file
        file_url = f"{DO_SPACES_ENDPOINT}/{DO_BUCKET_NAME}/{file_path}"

        file_info = {
            'filename': file_name,
            'device_type': device_type,
            'url': file_url,
            'profile_id': profile_id  # Assuming you have an 'id' variable available in your code
        }
        files_collection.insert_one(file_info)

        return file_url

    except NoCredentialsError:
        raise Exception('Credentials not available. Check your DigitalOcean Spaces access key and secret key.')
    except Exception as e:
        raise Exception(str(e))

# Create a profile image
@app.route('/profile/<id>/image', methods=['POST', 'DELETE'])
@jwt_required()
def upload_and_delete_image(id):
    try:
        file_name = None

        s3 = boto3.client('s3',
            aws_access_key_id='DO00FVYZELDGLP9XU3Y4',
            aws_secret_access_key='3SuOMJtlfNklPrhwv9U3FmkgnhVXbKU+u3fGG1zaZ/g',
            endpoint_url=DO_SPACES_ENDPOINT
        )

        if request.method == 'POST':
            # Check if the POST request has the file part
            if 'file' not in request.files or 'device_type' not in request.form:
                return jsonify({"error": "No file or device type provided"}), 400

            file = request.files['file']
            device_type = request.form['device_type']

            # If the user does not select a file, the browser submits an empty file without a filename
            if file.filename == '':
                return jsonify({"error": "No selected file"}), 400

            file_name = f"{file.filename}"

            # Upload the file to DigitalOcean Spaces and get the file URL
            file_url = upload_to_digitalocean(file, file_name, device_type, id)

            return jsonify({'message': 'Image uploaded successfully', 'file_url': file_url})

        elif request.method == 'DELETE':

            file_name = request.json.get('filename') or request.args.get('filename')

            if file_name is None:
                return jsonify({"error": "No file specified for deletion"}), 400

            # Delete the file from DigitalOcean Spaces
            s3 = boto3.client('s3',
            aws_access_key_id='DO00FVYZELDGLP9XU3Y4',
            aws_secret_access_key='3SuOMJtlfNklPrhwv9U3FmkgnhVXbKU+u3fGG1zaZ/g',
            endpoint_url=DO_SPACES_ENDPOINT
        )
            # filename = request.json.get('filename')  # Assuming you send the filename in the request body

            delete_file_from_digitalocean(file_name)

            s3.delete_object(Bucket= DO_BUCKET_NAME, Key=file_name)

            files_collection.delete_one({'filename': file_name})

            return {'message': f'{file_name} deleted successfully'}

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def delete_file_from_digitalocean(file_name):
    try:
        s3 = boto3.client('s3',
            aws_access_key_id='DO00FVYZELDGLP9XU3Y4',
            aws_secret_access_key='3SuOMJtlfNklPrhwv9U3FmkgnhVXbKU+u3fGG1zaZ/g',
            endpoint_url=DO_SPACES_ENDPOINT
        )

        # Delete the file from DigitalOcean Spaces
        s3.delete_object(Bucket=DO_BUCKET_NAME, Key=file_name)

    except NoCredentialsError:
        raise Exception('Credentials not available. Check your DigitalOcean Spaces access key and secret key.')
    except Exception as e:
        raise Exception(str(e))

def delete_file_from_mongodb(file_name):
    # Delete the file information from MongoDB
    files_collection.delete_one({'filename': file_name})

# Delete a profile image
@app.route('/profile/<id>/image/<filename>', methods=['DELETE'])
@jwt_required()
def delete_uploaded_image(id, filename):
    try:
        # Delete the file from DigitalOcean Spaces
        delete_file_from_digitalocean(filename)

        # Delete the file information from MongoDB
        delete_file_from_mongodb(filename)

        return {'message': f'File {filename} deleted successfully'}

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Initialize default toggle states
default_notifications = {
    'uploads': False,
    'milestone_completion': False,
    'survey_notification': False,
    'pause_all_notification': False,
    'daily_meditation_reminders': False
}

# Insert default toggles if not present
if notifications_collection.find_one({}) is None:
    notifications_collection.insert_one(default_notifications)

class NotificationResource(Resource):
    @jwt_required()
    def get(self, user_id):
        # Retrieve current toggle states for the given user_id
        user_object_id = ObjectId(user_id)
        notifications = notifications_collection.find_one({"_id": user_object_id})

        # Manually convert ObjectId to string
        if notifications:
            for key, value in notifications.items():
                if isinstance(value, ObjectId):
                    notifications[key] = str(value)

            return jsonify(notifications), 200
        else:
            return jsonify({"message": "User not found"}), 404

    @jwt_required()
    def post(self, user_id):
        data = request.get_json()

        # Validate data structure (customize based on your requirements)
        required_fields = ['notification_name', 'state']
        if not all(field in data for field in required_fields):
            return jsonify({'message': 'Missing required fields'}), 400

        notification_name = data['notification_name']
        state = data['state']

        # Check if notification_name is valid
        if notification_name not in default_notifications:
            return jsonify({'message': 'Invalid notification name'}), 400

        # Update the toggle state in the database for the given user_id
        user_object_id = ObjectId(user_id)
        notifications_collection.update_one({"_id": user_object_id}, {'$set': {notification_name: state}}, upsert=True)
        return jsonify({'message': f'Notification {notification_name} updated successfully for user {user_id}'}), 200

    @jwt_required()
    def put(self, user_id, notification_name):
        data = request.get_json()

        # Check if notification_name is valid
        if notification_name not in default_notifications:
            return jsonify({'message': 'Invalid notification name'}), 400

        # Update the toggle state in the database for the given user_id
        user_object_id = ObjectId(user_id)
        notifications_collection.update_one({"_id": user_object_id}, {'$set': {notification_name: data['state']}}, upsert=True)
        return jsonify({'message': f'Notification {notification_name} updated successfully for user {user_id}'}), 200

api.add_resource(NotificationResource, '/notification/<string:user_id>', '/notification/<string:user_id>/<string:notification_name>')


# Predefined set of available languages
available_languages = ['English', 'Spanish', 'French', 'German', 'Chinese', 'Japanese']

class LanguageResource(Resource):
    @jwt_required()
    def get(self, user_id):
        # Retrieve user's chosen language
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if user:
            return jsonify({'chosen_language': user.get('chosen_language', None)})
        else:
            return {'message': 'User not found'}, 404

    @jwt_required()
    def put(self, user_id):
        data = request.get_json()

        # Check if the chosen language is in the available languages
        chosen_language = data.get('chosen_language')
        if chosen_language not in available_languages:
            return {'message': 'Invalid language choice'}, 400

        # Update the chosen language in the database
        result = users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {'$set': {'chosen_language': chosen_language}},
            upsert=True
        )

        if result.upserted_id or result.modified_count > 0:
            return {'message': 'Chosen language updated successfully'}, 200
        else:
            return {'message': 'User not found'}, 404

api.add_resource(LanguageResource, '/language/<string:user_id>')

validation_rules = {
    "content": "required",
    "email": "required"
    }

# Create a contact
@app.route('/contact', methods=['POST'])
def create_contact():
    data = request.get_json()
    validation_errors = validate_data(data, validation_rules)

    if validation_errors:
        return jsonify({"errors": validation_errors}), 400

    inserted_id = contacts_collection.insert_one(data).inserted_id

    response_data = {
        "content": data.get("content"),
        "email": data.get("email"),
        "_id": str(inserted_id)
        # Add more fields as needed
    }

    return jsonify(response_data)

def validate_data(data, validation_rules):
    errors = []

    for field, rule in validation_rules.items():
        if rule == "required" and not data.get(field):
            errors.append(f"{field} is required.")
        elif rule == "optional" and field in data and not data.get(field):
            errors.append(f"{field} must be optional.")

    return errors

# Update a contact
@app.route('/contact/<id>', methods=['PUT'])
@jwt_required()
def update_contact(id):
    id = ObjectId(id)
    data = request.get_json()
    validation_errors = validate_data(data, validation_rules)

    if validation_errors:
        return jsonify({"errors": validation_errors}), 400
    
    existing_document = contacts_collection.find_one({"_id": id})

    if existing_document is None:
        return jsonify({"error": "Contact not found"}), 404

    result = contacts_collection.update_one({"_id": ObjectId(id)}, {"$set": data})

    response_data = {
        "content": data.get("content"),
        "email": data.get("email"),
        "_id": str(id)
        # Add more fields as needed
    }

    if result.matched_count == 0:
        return jsonify({"error": "Contact not found"}), 404
    elif result.modified_count == 0:
        return jsonify({"error": "Contact not updated"}), 404
    else:
        return jsonify(response_data)

# Get all contacts
@app.route('/contact', methods=['GET'])
@jwt_required()
def get_contacts():
    contacts = list(contacts_collection.find())
    data = []
    for contact in contacts:
        contact['_id'] = str(contact['_id']) 
        data.append(contact)
    return jsonify(data)

# Get a specific contact by ID
@app.route('/contact/<id>')
@jwt_required()
def contact(id):
    contact = contacts_collection.find_one({'_id':ObjectId(id)})
    if contact:
        contact["_id"] = str(contact["_id"])
        return contact
    else:
        return jsonify({"error": "Contact Not Found"}), 404

# Delete a contact
@app.route('/contact/<id>', methods=['DELETE'])
@jwt_required()
def delete_contact(id):
    id = ObjectId(id)
    result = contacts_collection.delete_one({"_id": ObjectId(id)})

    if result.deleted_count > 0:
        return jsonify({"message": "Contact deleted successfully"})
    else:
        return jsonify({"error": "Contact not found or not deleted"}), 404

validation_rules1 = {
    "content": "required",
    "files": "required"
    }

# Report A Problem
@app.route('/report', methods=['POST'])
def create_report():
    data = request.get_json()
    validation_errors = validate_data(data, validation_rules1)

    if validation_errors:
        return jsonify({"errors": validation_errors}), 400

    inserted_id = reports_collection.insert_one(data).inserted_id

    response_data = {
        "content": data.get("content"),
        "files": data.get("files"),
        "_id": str(inserted_id)
        # Add more fields as needed
    }

    return jsonify(response_data)

def validate_data(data, validation_rules1):
    errors = []

    for field, rule in validation_rules1.items():
        if rule == "required" and not data.get(field):
            errors.append(f"{field} is required.")
        elif rule == "optional" and field in data and not data.get(field):
            errors.append(f"{field} must be optional.")

    return errors

# Update a report
@app.route('/report/<id>', methods=['PUT'])
@jwt_required()
def update_report(id):
    id = ObjectId(id)
    data = request.get_json()
    validation_errors = validate_data(data, validation_rules1)

    if validation_errors:
        return jsonify({"errors": validation_errors}), 400
    
    existing_document = reports_collection.find_one({"_id": id})

    if existing_document is None:
        return jsonify({"error": "Report not found"}), 404

    result = reports_collection.update_one({"_id": ObjectId(id)}, {"$set": data})

    response_data = {
        "content": data.get("content"),
        "files": data.get("files"),
        "_id": str(id)
        # Add more fields as needed
    }

    if result.matched_count == 0:
        return jsonify({"error": "Report not found"}), 404
    elif result.modified_count == 0:
        return jsonify({"error": "Report not updated"}), 404
    else:
        return jsonify(response_data)

# Get all reports
@app.route('/report', methods=['GET'])
@jwt_required()
def get_reports():
    reports = list(reports_collection.find())
    data = []
    for report in reports:
        report['_id'] = str(report['_id']) 
        data.append(report)
    return jsonify(data)

# Get a specific report by ID
@app.route('/report/<id>')
@jwt_required()
def report(id):
    report = reports_collection.find_one({'_id':ObjectId(id)})
    if report:
        report["_id"] = str(report["_id"])
        return report
    else:
        return jsonify({"error": "Report Not Found"}), 404
# Delete a report
@app.route('/report/<id>', methods=['DELETE'])
@jwt_required()
def delete_report(id):
    id = ObjectId(id)
    result = reports_collection.delete_one({"_id": ObjectId(id)})

    if result.deleted_count > 0:
        return jsonify({"message": "Report deleted successfully"})
    else:
        return jsonify({"error": "Report not found or not deleted"}), 404

# ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
# MAX_FILE_SIZE_BYTES = 500 * 500 #10 * 1024 * 1024
# DO_SPACES_ENDPOINT = 'https://wild-cabarets.fra1.digitaloceanspaces.com'  # Replace with your Space URL
# DO_ACCESS_KEY = 'DO00H8HLFYNACV6LJ3GP'  # Replace with your DigitalOcean Spaces access key
# DO_SECRET_KEY = 'fKbFfbNG2PcuyLCZ79xjePWYjmCP9wGCNdWgfgxCTnY'  # Replace with your DigitalOcean Spaces secret key
# DO_BUCKET_NAME = 'fortywinks'  # Replace with your DigitalOcean Spaces bucket name

# # # Create a connection to DigitalOcean Spaces
# # s3 = boto3.client('s3', endpoint_url=DO_SPACES_ENDPOINT, aws_access_key_id=DO_ACCESS_KEY, aws_secret_access_key=DO_SECRET_KEY)

# def allowed_file_size(file):
#     return file.content_length <= MAX_FILE_SIZE_BYTES

# def allowed_file(filename):
#     return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# def upload_to_digitalocean(file, file_name, device_type, event_id):
#     try:
#         s3 = boto3.client('s3',
#             aws_access_key_id='DO00H8HLFYNACV6LJ3GP',
#             aws_secret_access_key='fKbFfbNG2PcuyLCZ79xjePWYjmCP9wGCNdWgfgxCTnY',
#             endpoint_url=DO_SPACES_ENDPOINT
#         )

#         # Create a folder with the specified device type
#         folder_path = f"{device_type}/"
#         file_path = os.path.join(folder_path, file_name)

#         # Upload the file to DigitalOcean Spaces
#         s3.upload_fileobj(file, DO_BUCKET_NAME, file_path)

#         # Get the public URL of the uploaded file
#         file_url = f"{DO_SPACES_ENDPOINT}/{DO_BUCKET_NAME}/{file_path}"

#         file_info = {
#             'filename': file_name,
#             'device_type': device_type,
#             'url': file_url,
#             'event_id': event_id  # Assuming you have an 'id' variable available in your code
#         }
#         files_collection.insert_one(file_info)

#         return file_url

#     except NoCredentialsError:
#         raise Exception('Credentials not available. Check your DigitalOcean Spaces access key and secret key.')
#     except Exception as e:
#         raise Exception(str(e))

# @app.route('/reports/<id>/image', methods=['POST', 'DELETE'])
# @jwt_required()
# def upload_and_delete_image(id):
#     try:
#         file_name = None

#         s3 = boto3.client('s3',
#             aws_access_key_id='DO00H8HLFYNACV6LJ3GP',
#             aws_secret_access_key='fKbFfbNG2PcuyLCZ79xjePWYjmCP9wGCNdWgfgxCTnY',
#             endpoint_url=DO_SPACES_ENDPOINT
#         )

#         if request.method == 'POST':
#             # Check if the POST request has the file part
#             if 'file' not in request.files or 'device_type' not in request.form:
#                 return jsonify({"error": "No file or device type provided"}), 400

#             file = request.files['file']
#             device_type = request.form['device_type']

#             # If the user does not select a file, the browser submits an empty file without a filename
#             if file.filename == '':
#                 return jsonify({"error": "No selected file"}), 400

#             file_name = f"{file.filename}"

#             # Upload the file to DigitalOcean Spaces and get the file URL
#             file_url = upload_to_digitalocean(file, file_name, device_type, id)

#             return jsonify({'message': 'Image uploaded successfully', 'file_url': file_url})

#         elif request.method == 'DELETE':

#             file_name = request.json.get('filename') or request.args.get('filename')

#             if file_name is None:
#                 return jsonify({"error": "No file specified for deletion"}), 400

#             # Delete the file from DigitalOcean Spaces
#             s3 = boto3.client('s3',
#                 aws_access_key_id='DO00H8HLFYNACV6LJ3GP',
#                 aws_secret_access_key='fKbFfbNG2PcuyLCZ79xjePWYjmCP9wGCNdWgfgxCTnY',
#                 endpoint_url=DO_SPACES_ENDPOINT
#             )
#             # filename = request.json.get('filename')  # Assuming you send the filename in the request body

#             delete_file_from_digitalocean(file_name)

#             s3.delete_object(Bucket= DO_BUCKET_NAME, Key=file_name)

#             files_collection.delete_one({'filename': file_name})

#             return {'message': f'{file_name} deleted successfully'}

#     except Exception as e:
#         return jsonify({'error': str(e)}), 500

# def delete_file_from_digitalocean(file_name):
#     try:
#         s3 = boto3.client('s3',
#             aws_access_key_id='DO00H8HLFYNACV6LJ3GP',
#             aws_secret_access_key='fKbFfbNG2PcuyLCZ79xjePWYjmCP9wGCNdWgfgxCTnY',
#             endpoint_url=DO_SPACES_ENDPOINT
#         )

#         # Delete the file from DigitalOcean Spaces
#         s3.delete_object(Bucket=DO_BUCKET_NAME, Key=file_name)

#     except NoCredentialsError:
#         raise Exception('Credentials not available. Check your DigitalOcean Spaces access key and secret key.')
#     except Exception as e:
#         raise Exception(str(e))

# def delete_file_from_mongodb(file_name):
#     # Delete the file information from MongoDB
#     files_collection.delete_one({'filename': file_name})

# @app.route('/reports/<id>/image/<filename>', methods=['DELETE'])
# @jwt_required()
# def delete_uploaded_image(id, filename):
#     try:

#         # file_name_in_digitalocean = f"{filename}"
#         # Delete the file from DigitalOcean Spaces
#         delete_file_from_digitalocean(filename)

#         # Delete the file information from MongoDB
#         delete_file_from_mongodb(filename)

#         return {'message': f'File {filename} deleted successfully'}

#     except Exception as e:
#         return jsonify({'error': str(e)}), 500

# validation_rules2 = {
#     "request": "required"
#     }

# # Create a support request
# @app.route('/supportrequest', methods=['POST'])
# def create_support():
#     data = request.get_json()
#     validation_errors = validate_data(data, validation_rules2)

#     if validation_errors:
#         return jsonify({"errors": validation_errors}), 400

#     inserted_id = supportrequests_collection.insert_one(data).inserted_id

#     response_data = {
#         "request": data.get("request"),
#         "_id": str(inserted_id)
#         # Add more fields as needed
#     }

#     return jsonify(response_data)

# def validate_data(data, validation_rules2):
#     errors = []

#     for field, rule in validation_rules1.items():
#         if rule == "required" and not data.get(field):
#             errors.append(f"{field} is required.")
#         elif rule == "optional" and field in data and not data.get(field):
#             errors.append(f"{field} must be optional.")

#     return errors

# Get all supportrequests
@app.route('/supportrequest', methods=['GET'])
@jwt_required()
def get_supportrequests():
    supportrequests = list(supportrequests_collection.find())
    data = []
    for supportrequest in supportrequests:
        supportrequest['_id'] = str(supportrequest['_id']) 
        data.append(supportrequest)
    return jsonify(data)

# Get a specific support request by ID
@app.route('/supportrequest/<id>')
@jwt_required()
def supportrequest(id):
    supportrequest = supportrequests_collection.find_one({'_id':ObjectId(id)})
    if supportrequest:
        supportrequest["_id"] = str(supportrequest["_id"])
        return supportrequest
    else:
        return jsonify({"error": "Support Request Not Found"}), 404

# Delete a support request
@app.route('/supportrequest/<id>', methods=['DELETE'])
@jwt_required()
def delete_supportrequest(id):
    id = ObjectId(id)
    supportrequest = supportrequests_collection.delete_one({"_id": ObjectId(id)})

    if supportrequest.deleted_count > 0:
        return jsonify({"message": "Support Request deleted successfully"})
    else:
        return jsonify({"error": "Support Request not found or not deleted"}), 404

class ThemePreferenceResource(Resource):
    @jwt_required()
    def get(self, user_id):
        # Retrieve the user's theme preference from the database
        user = users_collection.find_one({'_id': ObjectId(user_id)})

        if user:
            return {'theme': user.get('theme', 'light')}, 200
        else:
            return {'message': 'User not found'}, 404

    def put(self, user_id):
        data = request.get_json()

        # Validate theme preference value
        theme_preference = data.get('theme')

        if theme_preference not in ['light', 'dark']:
            return {'message': 'Invalid theme preference'}, 400

        # Update the user's theme preference in the database
        users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': {'theme': theme_preference}})

        return {'message': 'Theme preference updated successfully'}, 200

api.add_resource(ThemePreferenceResource, '/theme-preference/<string:user_id>')

class SubscriptionResource(Resource):
    @jwt_required()
    def post(self, user_id):
        data = request.get_json()

        # Validate required fields
        if 'duration' not in data:
            return {'message': 'Subscription duration is required'}, 400

        # Calculate the subscription expiry date based on the selected duration
        current_date = datetime.utcnow()
        duration = data['duration']
        expiry_date = current_date + timedelta(days=30 * duration)  # Assuming 30 days per month

        # Save the subscription details in the database
        subscription = {
            '_id': user_id,
            'expiry_date': expiry_date,
            'amount': calculate_subscription_amount(duration),
            'status': 'active',
            'duration': duration  # Add the 'duration' field
        }

        subscriptions_collection.insert_one(subscription)

        return {'message': 'Subscription confirmed successfully', 'user_id': str(user_id), 'duration': duration}, 201

    def get(self, user_id):
        # Retrieve the user's current active subscription details from the database
        subscription = subscriptions_collection.find_one({'_id': user_id, 'status': 'active'})

        if subscription:
            return {
                'expiry_date': subscription['expiry_date'].strftime('%Y-%m-%d %H:%M:%S'),
                'amount': subscription['amount'],
                'status': subscription['status'],
                'duration': subscription['duration']
            }, 200
        else:
            return {'message': 'No active subscription found for the user'}, 404

    def put(self, user_id):
        # Cancel the user's current subscription
        subscriptions_collection.update_one({'user_id': user_id, 'status': 'active'}, {'$set': {'status': 'canceled'}})
        return {'message': 'Subscription canceled successfully'}, 200

    def patch(self, user_id):
        # Renew the user's subscription for the same duration
        existing_subscription = subscriptions_collection.find_one({'_id': user_id, 'status': 'active'})

        if existing_subscription and 'duration' in existing_subscription:
            new_expiry_date = existing_subscription['expiry_date'] + timedelta(days=30 * existing_subscription['duration'])
            subscriptions_collection.update_one({'_id': user_id}, {'$set': {'expiry_date': new_expiry_date}})
            return {'message': 'Subscription renewed successfully'}, 200
        elif existing_subscription:
            # If duration information is missing, handle it accordingly (you might log an error)
            return {'message': 'Missing duration information for the existing subscription'}, 400
        else:
            # No active subscription found for the user
            return {'message': 'No active subscription found for the user'}, 404

def calculate_subscription_amount(duration):
    # This is a placeholder function, you can replace it with your logic to calculate the subscription amount
    # For simplicity, assuming $10 per month
    return 10 * duration

api.add_resource(SubscriptionResource, '/subscription/<string:user_id>')

# class UserLogoutResource(Resource):
#     def post(self, user_id):
#         print(f"Received user ID: {user_id}")
#         # Check if the user is logged in by retrieving the session from the sessions collection
#         session = sessions_collection.find_one({'_id': user_id, 'is_active': True})
#         print(f"Found session: {session}")

#         if session:
#             # If the session exists, mark it as inactive (logout)
#             sessions_collection.update_one({'_id': session['_id']}, {'$set': {'is_active': False}})
#             return {'message': 'User logged out successfully'}, 200
#         else:
#             return {'message': 'User is not currently logged in'}, 404

# api.add_resource(UserLogoutResource, '/logout/<string:user_id>')


@app.route('/getAllData', methods=['GET'])
def get_aggregated_data():
    aggregated_data = {}

    # Get a list of all collection names in the database
    collections = db.list_collection_names()

    for collection_name in collections:
        # Retrieve all documents from the current collection
        collection_data = list(db[collection_name].find())
          # Convert ObjectId to string in each document
        for entry in collection_data:
            entry['_id'] = str(entry['_id'])
        aggregated_data[collection_name] = collection_data
        
    return jsonify(aggregated_data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)