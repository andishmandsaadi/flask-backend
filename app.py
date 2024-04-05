from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://saadi:Flask123@localhost/flask_backend'
db = SQLAlchemy(app)

@app.route('/')
def home():
    return "Welcome to the Text Analysis Flask Backend!"

@app.route('/api/analyze-text', methods=['POST'])
def analyze_text():
    # Placeholder for text analysis logic
    text = request.json.get('text', '')
    return jsonify({"message": "Text received", "text": text})

class TextAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    result = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return '<TextAnalysis %r>' % self.text



if __name__ == '__main__':
    app.run(debug=True)
# CREATE USER 'saadi'@'%' IDENTIFIED BY 'Flask123';
# GRANT ALL PRIVILEGES ON flask_backend.* TO 'saadi'@'%';

