from flask import Flask, jsonify, request
from flask import make_response
from werkzeug.security import generate_password_hash
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
from models import User, TextAnalysis, EntityExtraction, LanguageDetection
from extensions import db
from flask_restx import Api, Resource, fields, Namespace
import json

from dotenv import load_dotenv
load_dotenv()

# Create a logs directory if it does not exist
if not os.path.exists('logs'):
    os.mkdir('logs')

def create_app():
    # create app
    app = Flask(__name__)

    # make database connection
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['FLASK_APP'] = os.getenv('FLASK_APP')
    app.config['FLASK_ENV'] = os.getenv('FLASK_ENV')
    db.init_app(app)

    # log configuration
    file_handler = RotatingFileHandler('logs/myapp.log', maxBytes=10240,
                                    backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)

    app.logger.setLevel(logging.INFO)
    app.logger.info('Flask application startup')

    jwt = JWTManager(app)

    api = Api(app, version='1.0', title='Text Analysis API', description='A Flask-based backend system for text analysis.')
    ns_auth = Namespace('auth', description='User authentication')
    ns_text = Namespace('text', description='Text analysis operations')
    ns_user = Namespace('user', description='User management')
    api.add_namespace(ns_auth)
    api.add_namespace(ns_text)
    api.add_namespace(ns_user)

    user_model = api.model('User', {
        'username': fields.String(required=True, description='The user username'),
        'password': fields.String(required=True, description='The user password')
    })

    text_model = api.model('Text', {
        'text': fields.String(required=True, description='Text to analyze or detect language')
    })
    user_update_model = api.model('UserUpdate', {
        'email': fields.String(required=True, description='The new email of the user')
    })

    user_delete_model = api.model('UserDelete', {
        'username': fields.String(required=True, description='The username of the user')
    })


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

    @jwt.unauthorized_loader
    def unauthorized_callback(callback):
        response_data = json.dumps({"msg": "Missing Authorization Header"})
        response = make_response(response_data, 401)
        response.mimetype = "application/json"
        return response

    @app.errorhandler(BadRequest)
    def handle_bad_request(e):
        # If the bad request is a result of a JSON decoding error
        if e.description.startswith("Failed to decode JSON object"):
            response_data = json.dumps({"error": "This endpoint expects a valid JSON object in the request body."})
            response = make_response(response_data, 400)
            response.mimetype = "application/json"
            return response
        # For other bad requests,
        response_data = json.dumps({"error": "Bad request. Please check your request data."})
        response = make_response(response_data, 400)
        response.mimetype = "application/json"
        return response

    @app.errorhandler(UnsupportedMediaType)
    def handle_unsupported_media_type(error):
        response_data = json.dumps({'error': 'This endpoint requires a JSON payload with the Content-Type header set to application/json.'})
        response = make_response(response_data, 415)
        response.mimetype = "application/json"
        return response


    # 404 error handler
    @app.errorhandler(404)
    def not_found_error(error):
        app.logger.error('404 Error: %s', (error))
        response_data = json.dumps({'error': 'Resource not found'})
        response = make_response(response_data, 404)
        response.mimetype = "application/json"
        return response

    # 500 error handler
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error('Server Error: %s', (error))
        response_data = json.dumps({'error': 'An unexpected error occurred'})
        response = make_response(response_data, 500)
        response.mimetype = "application/json"
        return response

    @ns_auth.route('/login')
    class UserLogin(Resource):
        @ns_auth.expect(user_model)
        def post(self):
            data = request.get_json()
            is_valid, missing_field = validate_required_fields(data, ['username', 'password'])
            if not is_valid:
                response_data = json.dumps({"error": f"The '{missing_field}' field is required and cannot be empty."})
                response = make_response(response_data, 400)
                response.mimetype = "application/json"
                return response
            app.logger.info('Processing login attempt')
            username = data.get('username', None)
            password = data.get('password', None)
            if authenticate(username, password):
                access_token = create_access_token(identity=username, expires_delta=timedelta(days=1))
                response_data = json.dumps({"access_token": access_token})
                response = make_response(response_data, 200)
                response.mimetype = "application/json"
                return response
            else:
                response_data = json.dumps({"msg": "Bad username or password"})
                response = make_response(response_data, 401)
                response.mimetype = "application/json"
                return response

    @ns_auth.route('/protected')
    class ProtectedResource(Resource):
        @jwt_required()
        def get(self):
            app.logger.info('Processing protected attempt')
            current_user = get_jwt_identity()
            response_data = json.dumps({'logged_in_as': current_user})
            response = make_response(response_data, 200)
            response.mimetype = "application/json"
            return response

    @ns_text.route('/analyze')
    class AnalyzeText(Resource):
        @jwt_required()
        @ns_text.expect(text_model)
        def post(self):
            app.logger.info('Processing analyze_text attempt')
            data = request.get_json()
            is_valid, missing_field = validate_required_fields(data, ['text'])
            if not is_valid:
                response_data = json.dumps({"error": f"The '{missing_field}' field is required and cannot be empty."})
                response = make_response(response_data, 400)
                response.mimetype = "application/json"
                return response
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

            response_data = json.dumps({"message": "Text received", "text": text, "sentiment": sentiment_result})
            response = make_response(response_data, 200)
            response.mimetype = "application/json"
            return response

    @ns_text.route('/extract-entities')
    class ExtractEntities(Resource):
        @jwt_required()
        @ns_text.expect(text_model)
        def post(self):
            app.logger.info('Processing extract_entities_route attempt')
            data = request.get_json()
            is_valid, missing_field = validate_required_fields(data, ['text'])
            if not is_valid:
                response_data = json.dumps({"error": f"The '{missing_field}' field is required and cannot be empty."})
                response = make_response(response_data, 400)
                response.mimetype = "application/json"
                return response
            text = data.get('text', '')
            entities = extract_entities(text)
            new_log = EntityExtraction(text=text, entities=str(entities))
            db.session.add(new_log)
            db.session.commit()

            response_data = json.dumps({"entities": entities})
            response = make_response(response_data, 200)
            response.mimetype = "application/json"
            return response

    @ns_text.route('/detect-language')
    class DetectLanguage(Resource):
        @jwt_required()
        @ns_text.expect(text_model)
        def post(self):
            app.logger.info('Processing detect_language_route attempt')
            data = request.get_json()
            is_valid, missing_field = validate_required_fields(data, ['text'])
            if not is_valid:
                response_data = json.dumps({"error": f"The '{missing_field}' field is required and cannot be empty."})
                response = make_response(response_data, 400)
                response.mimetype = "application/json"
                return response
            text = data.get('text', '')
            language = detect_language(text)
            new_log = LanguageDetection(text=text, language=language)
            db.session.add(new_log)
            db.session.commit()

            response_data = json.dumps({"language": language})
            response = make_response(response_data, 200)
            response.mimetype = "application/json"
            return response

    @ns_user.route('/')
    class CreateUser(Resource):
        @ns_user.expect(user_model)
        def post(self):
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
                response_data = json.dumps({"message": "User created successfully."})
                response = make_response(response_data, 201)
                response.mimetype = "application/json"
                return response
            except IntegrityError as e:
                db.session.rollback()
                # Check the error message or error code if you want to be more specific
                if 'Duplicate entry' in str(e.orig) and 'username' in str(e.orig):
                    response_data = json.dumps({"error": "Username already exists. Please choose a different username."})
                    response = make_response(response_data, 400)
                    response.mimetype = "application/json"
                    return response
                elif 'Duplicate entry' in str(e.orig) and 'email' in str(e.orig):
                    response_data = json.dumps({"error": "Email already exists. Please use a different email."})
                    response = make_response(response_data, 400)
                    response.mimetype = "application/json"
                    return response
                else:
                    response_data = json.dumps({"error": "An error occurred while creating the user. Please try again."})
                    response = make_response(response_data, 400)
                    response.mimetype = "application/json"
                    return response

    # update user
    @ns_user.route('/update/<string:username>')
    class UpdateUser(Resource):
        @jwt_required()
        @ns_user.expect(user_update_model)
        def put(self, username):
            app.logger.info('Processing update_user attempt')
            current_user_username = get_jwt_identity()

            user = User.query.filter_by(username=username).first()

            if user is None:
                response_data = json.dumps({"message": "User not found"})
                response = make_response(response_data, 404)
                response.mimetype = "application/json"
                return response

            if user.username != current_user_username:
                response_data = json.dumps({"msg": "Unauthorized to update this user"})
                response = make_response(response_data, 403)
                response.mimetype = "application/json"
                return response

            data = request.get_json()
            is_valid, missing_field = validate_required_fields(data, ['email'])
            if not is_valid:
                response_data = json.dumps({"error": f"The '{missing_field}' field is required and cannot be empty."})
                response = make_response(response_data, 400)
                response.mimetype = "application/json"
                return response
            user.email = data.get('email', user.email)
            db.session.commit()

            response_data = json.dumps({"message": "User updated successfully."})
            response = make_response(response_data, 200)
            response.mimetype = "application/json"
            return response


    # delete user
    @ns_user.route('/delete/<string:username>')
    class DeleteUser(Resource):
        @jwt_required()
        def delete(self, username):
            app.logger.info('Processing delete_user attempt')
            current_user_username = get_jwt_identity()
            user = User.query.filter_by(username=username).first()

            if user is None:
                response_data = json.dumps({"message": "User not found"})
                response = make_response(response_data, 404)
                response.mimetype = "application/json"
                return response

            if user.username != current_user_username:
                response_data = json.dumps({"msg": "Unauthorized to delete this user"})
                response = make_response(response_data, 403)
                response.mimetype = "application/json"
                return response

            db.session.delete(user)
            db.session.commit()

            response_data = json.dumps({"message": "User deleted successfully."})
            response = make_response(response_data, 200)
            response.mimetype = "application/json"
            return response


    # get user
    @ns_user.route('/<string:username>')
    class GetUser(Resource):
        @jwt_required()
        def get(self, username):
            app.logger.info('Processing get_user attempt')
            current_user_username = get_jwt_identity()

            if username != current_user_username:
                response_data = json.dumps({"msg": "Unauthorized to view this user"})
                response = make_response(response_data, 403)
                response.mimetype = "application/json"
                return response

            user = User.query.filter_by(username=username).first()
            if user:
                response_data = json.dumps({"username": user.username, "email": user.email})
                response = make_response(response_data, 200)
                response.mimetype = "application/json"
                return response
            else:
                response_data = json.dumps({"message": "User not found"})
                response = make_response(response_data, 404)
                response.mimetype = "application/json"
                return response

    return app


if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(debug=True)
