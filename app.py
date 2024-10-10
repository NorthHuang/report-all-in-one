import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'scripts'))
import config
from flask import Flask
from analysis import analysis_bp
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ["http://localhost:8000", "http://127.0.0.1:8000"]}})

app.register_blueprint(analysis_bp)

if __name__ == '__main__':
    app.run(debug=True)
