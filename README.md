
# PhishGuard — Phishing Detection Dashboard

PhishGuard is a Python cybersecurity project that analyzes URLs and email text for common phishing warning signs.

## Features

- URL risk analysis
- Email text analysis
- Risk score and explanatory findings
- Streamlit dashboard
- Automated unit tests

## Technologies

- Python
- Streamlit
- Regular expressions
- URL parsing
- unittest

## Setup

Install the required package:

    pip install -r requirements.txt

Run the application:

    python -m streamlit run app.py

## Run Tests

    python -m unittest test_phishguard -v

## Limitations

PhishGuard uses heuristic rules. Its scores are indicators, not probabilities or definitive verdicts. A low-risk result does not guarantee that a URL or email is safe. The application does not automatically visit submitted URLs.

## Future Improvements

- Domain reputation checks
- Threat intelligence integration
- More phishing test cases
- Improved detection rules
