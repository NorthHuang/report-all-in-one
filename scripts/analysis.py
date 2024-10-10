import json
from datetime import datetime
import os
import openai
from openai import OpenAI
from flask import Blueprint, request, jsonify
import pandas as pd
import joblib
import numpy as np

analysis_bp = Blueprint('analysis', __name__)
client = OpenAI(api_key=openai.api_key)

@analysis_bp.route('/analysis', methods=['POST'])
def analysis():
    if 'file' not in request.files:
        return jsonify({"status": "error", "error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "error": "No selected file"}), 400

    try:
        file_content = file.read().decode('utf-8')
        json_data = json.loads(file_content)

        model_path = os.path.dirname(__file__)
        voting_reg = joblib.load(os.path.join(model_path, '../model/voting_regressor_model.pkl'))  # model for prediction risk_score 
        voting_clf = joblib.load(os.path.join(model_path, '../model/voting_classifier_model.pkl'))  # model for classfication attack type(name)
        scaler = joblib.load(os.path.join(model_path, '../model/scaler.pkl'))
        encoder = joblib.load(os.path.join(model_path, '../model/encoder.pkl'))
        name_encoder = joblib.load(os.path.join(model_path, '../model/name_encoder.pkl'))  # Encoder for  classfication attack type(name)

        categorical_columns = ['protocol', 'traffic_direction', 'is_encrypted', 'destination_device']
        numeric_columns = ['packet_rate', 'data_rate', 'cpu_usage', 'memory_usage', 'disk_usage', 
                        'network_traffic_in', 'network_traffic_out']

        for data in json_data:
            data_without_timestamp = {key: value for key, value in data.items() if key != 'timestamp'}
            
            new_packet_data = pd.DataFrame(data_without_timestamp)
            
            new_packet_categorical_encoded = encoder.transform(new_packet_data[categorical_columns])
            new_packet_numeric_scaled = scaler.transform(new_packet_data[numeric_columns])
            new_packet_combined = np.concatenate([new_packet_numeric_scaled, new_packet_categorical_encoded], axis=1)
            
            predicted_risk_score = voting_reg.predict(new_packet_combined)
            predicted_attack_type_encoded = voting_clf.predict(new_packet_combined)
            predicted_attack_type = name_encoder.inverse_transform(predicted_attack_type_encoded)

            data['risk_score'] = round(predicted_risk_score[0], 2)
            data['attack_type'] = predicted_attack_type[0]

        recommendation=generate_recommendation(json_data)
        return jsonify({"status": "ok", "prediction": json_data, "recommendation": recommendation})

    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

def generate_recommendation(data):
    try:
        input_text = f"Here is some analysis data: {json.dumps(data)}.\n Based on this data, provide a recommendation in less than 50 words."
        completion = client.chat.completions.create(
            model="gpt-4o",
            messages=[
            {"role": "system", "content": "You are a helpful assistant."},
                {
                    "role": "user",
                    "content":input_text
                }
            ],
            max_tokens=50,
            temperature=0.7
        )
        recommendation = completion.choices[0].message.content
        return recommendation

    except Exception as e:
        print(f"Error generating recommendation: {e}")
        return "No recommendation available."
