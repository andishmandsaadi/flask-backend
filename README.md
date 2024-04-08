# Flask Text Analysis API

## Overview

This project is a Flask-based backend system designed to offer text analysis capabilities. It integrates AI for processing and analyzing text data, providing insights such as sentiment analysis, entity extraction, and language detection.

## Setup and Installation

### Prerequisites

- Python 3.8+
- MySQL
- pip
- virtualenv (optional)

### Installation Steps

1. Clone the repository:

`git clone https://github.com/andishmandsaadi/flask-bakend`

2. Navigate to the project directory and install dependencies:

`cd flask-backend`
`virtualenv venv`
`source venv/bin/activate`
`pip install -r requirements.txt`

3. Create a .env file in the project root directory and add the following configurations:

`FLASK_APP=app.py`
`FLASK_ENV=development`
`SECRET_KEY=your_secret_key`
`SQLALCHEMY_DATABASE_URI=mysql://username:password@localhost/dbname`

Replace username, password, localhost, and dbname with your MySQL database details and your_secret_key with a secure secret key.

4. Run the application:

`python app.py`


## API Endpoints

API endpoints documentation can be found via the below link:

`http://127.0.0.1:5000`

## AI Integration

### Sentiment Analysis with NLTK
When a user submits text for sentiment analysis, the application uses the NLTK library, renowned for its simplicity and effectiveness in handling linguistic data. The process involves several steps:

Preprocessing: The text is first cleaned and preprocessed. This includes removing punctuation, converting the text to lowercase, and tokenizing the text into individual words or tokens.
Sentiment Scoring: Using NLTK’s sentiment analyzer, the application calculates a sentiment score for the text. The score typically reflects the emotional tone of the text, categorizing it into positive, negative, or neutral sentiments.
Result Compilation: The sentiment scores, along with a comprehensive breakdown of the text's emotional tone (e.g., percentages of positivity, negativity, and neutrality), are compiled into a structured format.
Storage and Response: The analyzed results are stored in the database for historical reference and returned to the user, providing insightful feedback on the emotional undertone of their text submission.

### Entity Extraction with spaCy
For entity extraction, the application harnesses spaCy's robust NLP capabilities to identify and label named entities within the submitted text. The workflow is as follows:

Text Processing: Upon receiving text from the user, the application employs spaCy’s NLP engine to process the text. This step includes parsing and segmenting the text into tokens and sentences.
Entity Recognition: spaCy utilizes its pre-trained models to recognize named entities in the text. These entities can include people, places, organizations, dates, and more, each tagged with labels that denote their category.
Result Aggregation: The identified entities are aggregated, and their categories are summarized to provide a clear overview of the key subjects mentioned in the text.
Storage and Response: The entity extraction results are stored alongside the original text submission in the database. The entities, along with their labels, are then returned to the user, offering valuable insights into the subjects and concepts present in their text.

### Language Detection
Language detection is a crucial feature that allows the application to determine the language of the submitted text before processing it further. Although spaCy is primarily used for entity extraction, its capabilities extend to language detection through additional modules or integration with other libraries. The language detection process typically involves:

Language Identification: The application analyzes the text's characters and tokens to identify linguistic patterns that match known languages.
Determination of Language Code: Once the language is identified, it is represented by a standardized language code (e.g., "en" for English, "fr" for French), facilitating the selection of appropriate processing models for subsequent analysis.
Adaptation to Language: Knowing the language of the text allows the application to adapt its processing techniques, ensuring that sentiment analysis and entity extraction are as accurate as possible.
Response: The detected language code is stored with the text submission in the database and returned to the user, providing them with additional metadata about their submission.