from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token
from datetime import timedelta
from flask_jwt_extended import get_jwt_identity,jwt_required
import logging
from logging.handlers import RotatingFileHandler
import os
from ai_utils import extract_entities, detect_language,TextAnalyzer
from werkzeug.exceptions import BadRequest,UnsupportedMediaType
from sqlalchemy.exc import IntegrityError

# Create a logs directory if it does not exist
if not os.path.exists('logs'):
    os.mkdir('logs')

# create app
app = Flask(__name__)

# make database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://saadi:Flask123@localhost/flask_backend'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# log configuration
file_handler = RotatingFileHandler('logs/myapp.log', maxBytes=10240,
                                   backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)

app.logger.setLevel(logging.INFO)
app.logger.info('Flask application startup')

# JWT configuration
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Change this to a random secret key
jwt = JWTManager(app)


def authenticate(username, password):
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        return True
    else:
        return False

def validate_required_fields(data, required_fields):
    for field in required_fields:
        if field not in data or not data[field].strip():
            return False, field
    return True, ""

@app.route('/')
def home():
    return "Welcome to the Text Analysis Flask Backend!"

@app.errorhandler(BadRequest)
def handle_bad_request(e):
    # If the bad request is a result of a JSON decoding error, you can customize the message like so:
    if e.description.startswith("Failed to decode JSON object"):
        return jsonify({"error": "This endpoint expects a valid JSON object in the request body."}), 400
    # For other bad requests, you can return a generic message or customize further based on e.description
    return jsonify({"error": "Bad request. Please check your request data."}), 400

@app.errorhandler(UnsupportedMediaType)
def handle_unsupported_media_type(error):
    return jsonify({'error': 'This endpoint requires a JSON payload with the Content-Type header set to application/json.'}), 415

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    is_valid, missing_field = validate_required_fields(data, ['username', 'password'])
    if not is_valid:
        return jsonify({"error": f"The '{missing_field}' field is required and cannot be empty."}), 400
    app.logger.info('Processing login attempt')
    username = data.get('username', None)
    password = data.get('password', None)
    if authenticate(username, password):
        access_token = create_access_token(identity=username, expires_delta=timedelta(days=1))
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg": "Bad username or password"}), 401

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    app.logger.info('Processing protected attempt')
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

@app.route('/api/analyze-text', methods=['POST'])
@jwt_required()
def analyze_text():
    app.logger.info('Processing analyze_text attempt')
    data = request.get_json()
    is_valid, missing_field = validate_required_fields(data, ['text'])
    if not is_valid:
        return jsonify({"error": f"The '{missing_field}' field is required and cannot be empty."}), 400
    text = data.get('text', '')
    analyzer = TextAnalyzer()
    sentiment_result = analyzer.analyze_sentiment(text)

    # Create a new TextAnalysis log with the text and result
    new_analysis = TextAnalysis(
        text=text,
        sentiment_compound=sentiment_result.get('compound'),
        sentiment_neg=sentiment_result.get('neg'),
        sentiment_neu=sentiment_result.get('neu'),
        sentiment_pos=sentiment_result.get('pos')
    )
    db.session.add(new_analysis)
    db.session.commit()

    return jsonify({"message": "Text received", "text": text, "sentiment": sentiment_result})

@app.route('/api/extract-entities', methods=['POST'])
@jwt_required()
def extract_entities_route():
    app.logger.info('Processing extract_entities_route attempt')
    data = request.get_json()
    is_valid, missing_field = validate_required_fields(data, ['text'])
    if not is_valid:
        return jsonify({"error": f"The '{missing_field}' field is required and cannot be empty."}), 400
    text = data.get('text', '')
    entities = extract_entities(text)
    new_log = EntityExtraction(text=text, entities=str(entities))
    db.session.add(new_log)
    db.session.commit()
    return jsonify({"entities": entities})

@app.route('/api/detect-language', methods=['POST'])
@jwt_required()
def detect_language_route():
    app.logger.info('Processing detect_language_route attempt')
    data = request.get_json()
    is_valid, missing_field = validate_required_fields(data, ['text'])
    if not is_valid:
        return jsonify({"error": f"The '{missing_field}' field is required and cannot be empty."}), 400
    text = data.get('text', '')
    language = detect_language(text)
    new_log = LanguageDetection(text=text, language=language)
    db.session.add(new_log)
    db.session.commit()
    return jsonify({"language": language})

@app.route('/users', methods=['POST'])
def create_user():
    app.logger.info('Processing create_user attempt')
    data = request.get_json()

    new_user = User(
        username=data['username'],
        email=data['email'],
        password_hash=generate_password_hash(data['password'])
    )

    db.session.add(new_user)
    try:
        db.session.commit()
        return jsonify({"message": "User created successfully."}), 201
    except IntegrityError as e:
        db.session.rollback()
        # Check the error message or error code if you want to be more specific
        if 'Duplicate entry' in str(e.orig) and 'username' in str(e.orig):
            return jsonify({"error": "Username already exists. Please choose a different username."}), 400
        elif 'Duplicate entry' in str(e.orig) and 'email' in str(e.orig):
            return jsonify({"error": "Email already exists. Please use a different email."}), 400
        else:
            return jsonify({"error": "An error occurred while creating the user. Please try again."}), 400

# update user
@app.route('/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    app.logger.info('Processing update_user attempt')
    current_user_username = get_jwt_identity()
    user = User.query.get_or_404(user_id)

    if user.username != current_user_username:
        return jsonify({"msg": "Unauthorized to update this user"}), 403

    data = request.get_json()
    is_valid, missing_field = validate_required_fields(data, ['email'])
    if not is_valid:
        return jsonify({"error": f"The '{missing_field}' field is required and cannot be empty."}), 400
    user.email = data.get('email', user.email)
    db.session.commit()
    return jsonify({"message": "User updated successfully."}), 200


# delete user
@app.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    app.logger.info('Processing delete_user attempt')
    current_user_username = get_jwt_identity()
    user = User.query.get_or_404(user_id)

    if user.username != current_user_username:
        return jsonify({"msg": "Unauthorized to delete this user"}), 403

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully."}), 200


# get user
@app.route('/users/<username>', methods=['GET'])
@jwt_required()
def get_user(username):
    app.logger.info('Processing get_user attempt')
    current_user_username = get_jwt_identity()

    if username != current_user_username:
        return jsonify({"msg": "Unauthorized to view this user"}), 403

    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({"username": user.username, "email": user.email}), 200
    else:
        return jsonify({"message": "User not found"}), 404


# 404 error handler
@app.errorhandler(404)
def not_found_error(error):
    app.logger.error('404 Error: %s', (error))
    return jsonify({'error': 'Resource not found'}), 404

# 500 error handler
@app.errorhandler(500)
def internal_error(error):
    app.logger.error('Server Error: %s', (error))
    return jsonify({'error': 'An unexpected error occurred'}), 500

# TextAnalysis db table
class TextAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    sentiment_compound = db.Column(db.Float, nullable=True)
    sentiment_neg = db.Column(db.Float, nullable=True)
    sentiment_neu = db.Column(db.Float, nullable=True)
    sentiment_pos = db.Column(db.Float, nullable=True)

    def __repr__(self):
        return '<TextAnalysis %r>' % self.text

# User db table
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# EntityExtraction db table
class EntityExtraction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    entities = db.Column(db.Text, nullable=True)

# LanguageDetection db table
class LanguageDetection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    language = db.Column(db.String(20), nullable=False)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
