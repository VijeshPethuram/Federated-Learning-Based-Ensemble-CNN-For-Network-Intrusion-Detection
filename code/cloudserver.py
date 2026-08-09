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

class cloudserver:
    def __init__(self):
        self.selectedfeatures = [
            "protocol_type", "service", "flag", "land", "duration", "src_bytes", "dst_bytes", 
            "wrong_fragment", "urgent", "hot", "srv_count", "serror_rate", "srv_serror_rate", 
            "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", 
            "dst_host_count", "dst_host_srv_count", 
            "dst_host_same_srv_rate", "dst_host_diff_srv_rate", 
            "dst_host_same_src_port_rate", "dst_host_serror_rate", 
            "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
        ]                    
        self.machinelearningmodels = {
            "svm": SVC(probability=True),
            "knn": KNeighborsClassifier(),
            "dt": DecisionTreeClassifier()
        }
        self.ensemble = None
        self.standardscaler = StandardScaler()
        self.onehotencoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
        self.data = pd.read_csv("KDD.csv")
        self.temporarybuffer = pd.DataFrame(columns=self.data.columns)
        self.trainallmodels()
    
    def buildcnn(self, inputshape):
        model = Sequential()
        model.add(Input(shape=(inputshape, 1)))  
        model.add(Conv1D(64, 2, activation='relu'))
        model.add(Flatten())  
        model.add(Dense(800, activation='relu'))  
        model.add(Dropout(0.5))
        model.add(Dense(1, activation='sigmoid'))
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        return model
    
    def preprocessdata(self, data, training=False):
        categoricalfeatures = ["protocol_type", "service", "flag", "land"]
        data[categoricalfeatures] = data[categoricalfeatures].fillna('NA').astype(str)
        numericalfeatures = self.selectedfeatures[4:]
        data[numericalfeatures] = data[numericalfeatures].fillna(0)
        data = data[self.selectedfeatures]

        if training:
            encodedcategories = self.onehotencoder.fit_transform(data[categoricalfeatures])
        else:
            encodedcategories = self.onehotencoder.transform(data[categoricalfeatures])

        if training:
            scalednumbers = self.standardscaler.fit_transform(data[numericalfeatures])
        else:
            scalednumbers = self.standardscaler.transform(data[numericalfeatures])
        
        return np.hstack((encodedcategories, scalednumbers))
    
    def trainallmodels(self):
        if not self.temporarybuffer.empty:
            combineddata = pd.concat([self.data, self.temporarybuffer], ignore_index=True)
        else:
            combineddata = self.data

        X = combineddata[self.selectedfeatures]
        y = combineddata["classnum"]

        Xtrain, Xtest, ytrain, ytest = train_test_split(X, y, test_size=0.3, random_state=42)
        Xtrainprocessed = self.preprocessdata(Xtrain, training=True)
        Xtestprocessed = self.preprocessdata(Xtest, training=False)

        numfeatures = Xtrainprocessed.shape[1]  

        Xtraincnn = Xtrainprocessed.reshape(Xtrainprocessed.shape[0], numfeatures, 1)
        Xtestcnn = Xtestprocessed.reshape(Xtestprocessed.shape[0], numfeatures, 1)

        self.machinelearningmodels["cnn"] = self.buildcnn(numfeatures)  

        for name, model in self.machinelearningmodels.items():
            if name == "cnn":
                model.fit(Xtraincnn, ytrain, epochs=10, batch_size=32, verbose=1)
                ypred = (model.predict(Xtestcnn) > 0.5).astype("int32")
            else:
                model.fit(Xtrainprocessed, ytrain)
                ypred = model.predict(Xtestprocessed)
            acc = accuracy_score(ytest, ypred)
            print(f"{name} Acc: {acc:.4f}")

        self.ensemble = VotingClassifier(
            estimators=[(name, model) for name, model in self.machinelearningmodels.items() if name != "cnn"],
            voting='soft'
        )
        self.ensemble.fit(Xtrainprocessed, ytrain)
        enspre = self.ensemble.predict(Xtestprocessed)
        ensacc = accuracy_score(ytest, enspre)
        
        
        cnnpredictions = (self.machinelearningmodels["cnn"].predict(Xtestcnn) > 0.5).astype("int32")
        combinedpredictions = (enspre + cnnpredictions.flatten()) / 2
        combinedpredictions = (combinedpredictions > 0.5).astype("int32")
        combinedacc = accuracy_score(ytest, combinedpredictions)
        print("Combined CNN and Ensemble Accuracy is:", combinedacc)

    def predict(self, packet):
        packetdf = pd.DataFrame([packet])
        Xprocessed = self.preprocessdata(packetdf, training=False)
        numfeatures = Xprocessed.shape[1]  
        Xcnn = Xprocessed.reshape(1, numfeatures, 1)
        cnnpredict = (self.machinelearningmodels["cnn"].predict(Xcnn) > 0.5).astype("int32")[0][0]
        ensemblepredict = self.ensemble.predict(Xprocessed)
        
        finalprediction = "anomaly" if ensemblepredict[0] == "anomaly" or cnnpredict==1  else "normal"
        
        if finalprediction == "anomaly":
            self.temporarybuffer = pd.concat([self.temporarybuffer, packetdf], ignore_index=True)
        return finalprediction

cloudserver = cloudserver()

def periodictraining():
    while True:
        time.sleep(3600)
        cloudserver.trainallmodels()

threading.Thread(target=periodictraining, daemon=True).start()

entityid = "cloud_server_1"
sessionkey = None

def registerwithtra():
    global sessionkey
    response = requests.post(
        "http://localhost:6000/register",
        json={"entity_id": entityid, "entity_type": "cloud_server"}
    )
    if response.status_code == 201:
        sessionkey = response.json()["session_key"]
        print("Cloud server registered with TRA. SKEY: ",sessionkey)
    else:
        print("registration error")

def validaterequest(headers):
    entityid = headers.get("Entity-ID")
    nonce = headers.get("Nonce")
    receivedhmac = headers.get("HMAC")
    
    if not all([entityid, nonce, receivedhmac]):
        return False
    
    response = requests.post(
        "http://localhost:6000/authenticate",
        json={"entity_id": entityid, "nonce": nonce, "hmac": receivedhmac}
    )
    return response.status_code == 200

@app.route('/predict', methods=['POST'])
def predictpacket():
    if not validaterequest(request.headers):
        return jsonify({"error": "Authentication failed"}), 401
    
    packet = request.json
    prediction = cloudserver.predict(packet)
    return jsonify({"prediction": prediction})

@app.route('/status', methods=['GET'])
def showstatus():
    stat = "Ready."
    return render_template('status.html', status=stat)

registerwithtra()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)