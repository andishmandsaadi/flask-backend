from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from ai_utils import TextAnalyzer
import spacy
from langdetect import detect

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://saadi:Flask123@localhost/flask_backend'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Load spaCy's language model
nlp = spacy.load("en_core_web_sm")


@app.route('/')
def home():
    return "Welcome to the Text Analysis Flask Backend!"

@app.route('/api/analyze-text', methods=['POST'])
def analyze_text():
    text = request.json.get('text', '')
    analyzer = TextAnalyzer()
    sentiment_result = analyzer.analyze_sentiment(text)

    # You might want to save the result to the database here

    return jsonify({"message": "Text received", "text": text, "sentiment": sentiment_result})

@app.route('/api/extract-entities', methods=['POST'])
def extract_entities():
    data = request.get_json()
    text = data.get('text', '')
    doc = nlp(text)
    entities = [(ent.text, ent.label_) for ent in doc.ents]
    return jsonify({"entities": entities})

@app.route('/api/detect-language', methods=['POST'])
def detect_language():
    data = request.get_json()
    text = data.get('text', '')
    language = detect(text)
    return jsonify({"language": language})

@app.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()
    new_user = User(username=data['username'], email=data['email'])
    new_user.set_password(data['password'])
    db.session.add(new_user)
    try:
        db.session.commit()
        return jsonify({"message": "User created successfully."}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400

@app.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    user.email = data.get('email', user.email)
    db.session.commit()
    return jsonify({"message": "User updated successfully."}), 200

@app.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully."}), 200

@app.route('/users/<username>', methods=['GET'])
def get_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({"username": user.username, "email": user.email}), 200
    else:
        return jsonify({"message": "User not found"}), 404


class TextAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    result = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return '<TextAnalysis %r>' % self.text

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    submissions = db.relationship('Submission', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    submitted_at = db.Column(db.DateTime, nullable=False)
    results = db.relationship('AnalysisResult', backref='submission', lazy=True)

class AnalysisResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    submission_id = db.Column(db.Integer, db.ForeignKey('submission.id'), nullable=False)
    result = db.Column(db.Text, nullable=False)
    analyzed_at = db.Column(db.DateTime, nullable=False)



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
# CREATE USER 'saadi'@'%' IDENTIFIED BY 'Flask123';
# GRANT ALL PRIVILEGES ON flask_backend.* TO 'saadi'@'%';

