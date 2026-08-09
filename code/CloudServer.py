from flask import Flask, render_template, request, jsonify
import pandas as pd
import numpy as np
from sklearn.ensemble import VotingClassifier
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import threading
import time

app = Flask(__name__)

class CloudServer:
    def __init__(self):
        self.models = {
            "svm": SVC(probability=True),
            "knn": KNeighborsClassifier(),
            "dt": DecisionTreeClassifier()
        }
        self.ensemble = None
        self.scaler = StandardScaler()
        self.encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
        
        self.selected_features = [
            "protocol_type", "service", "flag", "land", "duration", "src_bytes", "dst_bytes", 
            "wrong_fragment", "urgent", "hot", "srv_count", "serror_rate", "srv_serror_rate", 
            "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", 
            "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", 
            "dst_host_same_srv_rate", "dst_host_diff_srv_rate", 
            "dst_host_same_src_port_rate", "dst_host_serror_rate", 
            "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
        ]
        
        self.dataset = pd.read_csv("KDDTrain+.csv") 
        self.dataset=self.dataset[:20000]
        self.buffer = pd.DataFrame(columns=self.dataset.columns)
        self.train_model()

    def preprocess_data(self, data, training=False):
        categorical_features = ["protocol_type", "service", "flag", "land"]
        for feature in categorical_features:
            data[feature] = data[feature].fillna('NA').astype(str)

        numerical_features = [
            "duration", "src_bytes", "dst_bytes", "wrong_fragment", "urgent", "hot",
            "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", 
            "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", 
            "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", 
            "dst_host_same_srv_rate", "dst_host_diff_srv_rate", 
            "dst_host_same_src_port_rate", 
            "dst_host_serror_rate", "dst_host_srv_serror_rate", 
            "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
        ]

        data[numerical_features] = data[numerical_features].fillna(0)

        data = data[self.selected_features]
        if data[categorical_features].isnull().any().any():
            data[categorical_features] = data[categorical_features].fillna('NA') 

        if training:
            encoded_categorical = self.encoder.fit_transform(data[categorical_features])
        else:
            encoded_categorical = self.encoder.transform(data[categorical_features])
        
        if training:
            scaled_numerical = self.scaler.fit_transform(data[numerical_features])
        else:
            scaled_numerical = self.scaler.transform(data[numerical_features])
        
        return np.hstack((encoded_categorical, scaled_numerical))

    def train_model(self):
        print("Training ensemble model...")
        X = self.dataset[self.selected_features]
        y = self.dataset["classnum"]
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        
        X_train_preprocessed = self.preprocess_data(X_train, training=True)
        X_test_preprocessed = self.preprocess_data(X_test, training=False)
                
        for name, model in self.models.items():
            model.fit(X_train_preprocessed, y_train)
            y_pred = model.predict(X_test_preprocessed)
            accuracy = accuracy_score(y_test, y_pred)
            print(f"{name} Model Accuracy: {accuracy:.4f}")
        
        self.ensemble = VotingClassifier(
            estimators=[(name, model) for name, model in self.models.items()],
            voting='soft'
        )
        self.ensemble.fit(X_train_preprocessed, y_train)
        
        ensemble_predictions = self.ensemble.predict(X_test_preprocessed)
        ensemble_accuracy = accuracy_score(y_test, ensemble_predictions)
        print(f"Ensemble Model Accuracy: {ensemble_accuracy:.4f}")
        

    def predict(self, packet):
        packet_df = pd.DataFrame([packet])
        print("PacketDF:\n", packet_df)
        X_preprocessed = self.preprocess_data(packet_df, training=False)
        prediction = self.ensemble.predict(X_preprocessed)
        return prediction[0]

    def retrain_from_buffer(self):
        if self.buffer.empty:
            print("No new data for retraining.")
            return
        
        print("Retraining model with buffered data...")
        self.dataset = pd.concat([self.dataset, self.buffer], ignore_index=True)
        self.buffer = self.buffer.iloc[0:0]  
        self.train_model()

cloud_server = CloudServer()

@app.route('/predict', methods=['POST'])
def predict_packet():
    packet = request.json
    print("Received: ", str(packet))
    prediction = cloud_server.predict(packet)
    
    if prediction == "anomaly":
        cloud_server.buffer = pd.concat([cloud_server.buffer, pd.DataFrame([packet])], ignore_index=True)
    
    return jsonify({"prediction": prediction})

def periodic_retraining():
    while True:
        time.sleep(3600)
        cloud_server.retrain_from_buffer()

threading.Thread(target=periodic_retraining, daemon=True).start()

@app.route('/predict', methods=['GET'])
def displaystatus():
    model_status = "Ready."  
    return render_template('status.html', status=model_status)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)