import nltk
from nltk.sentiment import SentimentIntensityAnalyzer

class TextAnalyzer:
    def __init__(self):
        # Ensure the VADER lexicon is available
        nltk.download('vader_lexicon', quiet=True)
        self.analyzer = SentimentIntensityAnalyzer()

    def analyze_sentiment(self, text):
        return self.analyzer.polarity_scores(text)
