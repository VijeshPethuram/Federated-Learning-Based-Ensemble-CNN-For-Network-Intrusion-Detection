import threading
from flask import Flask, app, render_template, request, jsonify
import pandas as pd
import hmac
import hashlib
import numpy as np
import requests
from sklearn.ensemble import VotingClassifier
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import threading
import time
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Conv1D, Flatten, Dropout, Input
app = Flask(__name__)
class CloudSrvr:
    def __init__(self):
        self.selectdfeats = [
            "protocol_type", "service", "flag", "land", "duration", "src_bytes", "dst_bytes", 
            "wrong_fragment", "urgent", "hot", "srv_count", "serror_rate", "srv_serror_rate", 
            "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", 
            "dst_host_count", "dst_host_srv_count", 
            "dst_host_same_srv_rate", "dst_host_diff_srv_rate", 
            "dst_host_same_src_port_rate", "dst_host_serror_rate", 
            "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
        ]                    
        self.machinemodels = {
            "svm": SVC(probability=True),
            "knn": KNeighborsClassifier(),
            "dt": DecisionTreeClassifier()
        }
        self.ensem = None
        self.standscalr = StandardScaler()
        self.onehotenc = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
        self.data = pd.read_csv("KDD.csv").iloc[:7000]
        self.tempbuffr = pd.DataFrame(columns=self.data.columns)
        self.trainall()
    
    def makecnn(self, input_shape):
        modl = Sequential()
        modl.add(Input(shape=(input_shape, 1)))  
        modl.add(Conv1D(64, 2, activation='relu'))
        modl.add(Flatten())  
        modl.add(Dense(800, activation='relu'))  
        modl.add(Dropout(0.5))
        modl.add(Dense(1, activation='sigmoid'))
        modl.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        return modl
    
    def prepdata(self, data, trainng=False):
        catfeats = ["protocol_type", "service", "flag", "land"]
        data[catfeats] = data[catfeats].fillna('NA').astype(str)
        numfeats = self.selectdfeats[4:]
        data[numfeats] = data[numfeats].fillna(0)
        data = data[self.selectdfeats]

        if trainng:
            encat = self.onehotenc.fit_transform(data[catfeats])
        else:
            encat = self.onehotenc.transform(data[catfeats])

        if trainng:
            scalenum = self.standscalr.fit_transform(data[numfeats])
        else:
            scalenum = self.standscalr.transform(data[numfeats])
        
        return np.hstack((encat, scalenum))
    def trainall(self):
        if not self.tempbuffr.empty:
            data_combined = pd.concat([self.data, self.tempbuffr], ignore_index=True)
        else:
            data_combined = self.data

        X = data_combined[self.selectdfeats]
        y = data_combined["classnum"]

        Xtrain, Xtest, ytrain, ytest = train_test_split(X, y, test_size=0.3, random_state=42)
        Xtrainpre = self.prepdata(Xtrain, trainng=True)
        Xtestpre = self.prepdata(Xtest, trainng=False)

        num_features = Xtrainpre.shape[1]  

        Xtraincnn = Xtrainpre.reshape(Xtrainpre.shape[0], num_features, 1)
        Xtestcnn = Xtestpre.reshape(Xtestpre.shape[0], num_features, 1)

        self.machinemodels["cnn"] = self.makecnn(num_features)  

        for nam, mdl in self.machinemodels.items():
            if nam == "cnn":
                mdl.fit(Xtraincnn, ytrain, epochs=1, batch_size=32, verbose=1)
                ypred = (mdl.predict(Xtestcnn) > 0.5).astype("int32")
            else:
                mdl.fit(Xtrainpre, ytrain)
                ypred = mdl.predict(Xtestpre)
            acc = accuracy_score(ytest, ypred)
            print(f"{nam} Acc: {acc:.4f}")

        self.ensem = VotingClassifier(
            estimators=[(nam, mdl) for nam, mdl in self.machinemodels.items() if nam != "cnn"],
            voting='soft'
        )
        self.ensem.fit(Xtrainpre, ytrain)
        enspre = self.ensem.predict(Xtestpre)
        ensacc = accuracy_score(ytest, enspre)
        print("Ensemble Accuracy is:", ensacc)

    def predict(self, packet):
        packet_df = pd.DataFrame([packet])
        Xpreprocessed = self.prepdata(packet_df, trainng=False)
        num_features = Xpreprocessed.shape[1]  
        X_cnn = Xpreprocessed.reshape(1, num_features, 1)
        cnnpredict = (self.machinemodels["cnn"].predict(X_cnn) > 0.5).astype("int32")[0][0]
        ensemblepredict = self.ensem.predict(Xpreprocessed)
        final_prediction = "anomaly" if ensemblepredict[0] == "anomaly" or cnnpredict == 1 else "normal"
        if final_prediction == "anomaly":
            self.tempbuffr = pd.concat([self.tempbuffr, packet_df], ignore_index=True)
        return final_prediction
cloudsrv = CloudSrvr()

def periodtrain():
    while True:
        time.sleep(3600)
        cloudsrv.trainall()

threading.Thread(target=periodtrain, daemon=True).start()



ENTITY_ID = "cloud_server_1"
SESSION_KEY = None

def register_with_tra():
    global SESSION_KEY
    response = requests.post(
        "http://localhost:6000/register",
        json={"entity_id": ENTITY_ID, "entity_type": "cloud_server"}
    )
    if response.status_code == 201:
        SESSION_KEY = response.json()["session_key"]
        print("Cloud server registered with TRA. SKEY: ",SESSION_KEY)

def validate_request(headers):
    entity_id = headers.get("Entity-ID")
    nonce = headers.get("Nonce")
    received_hmac = headers.get("HMAC")
    
    if not all([entity_id, nonce, received_hmac]):
        return False
    
    # Verify with TRA
    response = requests.post(
        "http://localhost:6000/authenticate",
        json={"entity_id": entity_id, "nonce": nonce, "hmac": received_hmac}
    )
    return response.status_code == 200

@app.route('/predict', methods=['POST'])
def predict_packet():
    if not validate_request(request.headers):
        return jsonify({"error": "Authentication failed"}), 401
    
    # Original prediction logic
    packet = request.json
    prediction = cloudsrv.predict(packet)
    return jsonify({"prediction": prediction})

@app.route('/status', methods=['GET'])
def showstatus():
    stat = "Ready."
    return render_template('status.html', status=stat)

# Initialize
register_with_tra()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
