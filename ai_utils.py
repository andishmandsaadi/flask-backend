import nltk
from nltk.sentiment import SentimentIntensityAnalyzer
import spacy
from langdetect import detect

# Load spaCy's language model
nlp = spacy.load("en_core_web_sm")

class TextAnalyzer:
    def __init__(self):
        # Ensure the VADER lexicon is available
        nltk.download('vader_lexicon', quiet=True)
        self.analyzer = SentimentIntensityAnalyzer()

    def analyze_sentiment(self, text):
        return self.analyzer.polarity_scores(text)

def extract_entities(text):
    doc = nlp(text)
    return [(ent.text, ent.label_) for ent in doc.ents]

def detect_language(text):
    return detect(text)