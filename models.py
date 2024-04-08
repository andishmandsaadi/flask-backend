from extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
import json

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

    def set_entities(self, entities_list):
        self.entities = json.dumps(entities_list)

    def get_entities(self):
        return json.loads(self.entities)

# LanguageDetection db table
class LanguageDetection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    language = db.Column(db.String(20), nullable=True)