from flask import Flask, render_template, request, jsonify
import pandas as pd
import numpy as np
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
from tensorflow.keras.layers import Dense, Conv1D, Flatten, Dropout
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.layers import Input

app=Flask(__name__)

class CloudServer:
    def __init__(self):
        self.selectedfeatures=[
            "protocol_type","service","flag","land","duration","src_bytes","dst_bytes", 
            "wrong_fragment","urgent","hot","srv_count","serror_rate","srv_serror_rate", 
            "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate", 
            "srv_diff_host_rate","dst_host_count","dst_host_srv_count", 
            "dst_host_same_srv_rate","dst_host_diff_srv_rate", 
            "dst_host_same_src_port_rate","dst_host_serror_rate", 
            "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate"
        ]
        self.models={
            "svm":SVC(probability=True),
            "knn":KNeighborsClassifier(),
            "dt":DecisionTreeClassifier(),
            "cnn":self.createcnnmodel()  
        }
        self.ensemble=None
        self.scaler=StandardScaler()
        self.encoder=OneHotEncoder(sparse_output=False,handle_unknown='ignore')
        
        self.dataset=pd.read_csv("KDDTrain+.csv") 
        self.dataset=self.dataset[:20000]
        self.buffer=pd.DataFrame(columns=self.dataset.columns)
        self.trainmodel()

    def createcnnmodel(self):
        model=Sequential()
        model.add(Input(shape=(27,1)))  
        model.add(Conv1D(64,2,activation='relu'))
        model.add(Flatten())  
        model.add(Dense(800,activation='relu'))  
        model.add(Dropout(0.5))
        model.add(Dense(1,activation='sigmoid'))
        model.compile(optimizer='adam',loss='binary_crossentropy',metrics=['accuracy'])
        return model

    def preprocessdata(self,data,training=False):
        categoricalfeatures=["protocol_type","service","flag","land"]
        for feature in categoricalfeatures:
            data[feature]=data[feature].fillna('NA').astype(str)

        numericalfeatures=[
            "duration","src_bytes","dst_bytes","wrong_fragment","urgent","hot",
            "srv_count","serror_rate","srv_serror_rate","rerror_rate", 
            "srv_rerror_rate","same_srv_rate","diff_srv_rate", 
            "srv_diff_host_rate","dst_host_count","dst_host_srv_count", 
            "dst_host_same_srv_rate","dst_host_diff_srv_rate", 
            "dst_host_same_src_port_rate", 
            "dst_host_serror_rate","dst_host_srv_serror_rate", 
            "dst_host_rerror_rate","dst_host_srv_rerror_rate"
        ]

        data[numericalfeatures]=data[numericalfeatures].fillna(0)

        data=data[self.selectedfeatures]
        if data[categoricalfeatures].isnull().any().any():
            data[categoricalfeatures]=data[categoricalfeatures].fillna('NA') 

        if training:
            encodedcategorical=self.encoder.fit_transform(data[categoricalfeatures])
        else:
            encodedcategorical=self.encoder.transform(data[categoricalfeatures])
        
        if training:
            scalednumerical=self.scaler.fit_transform(data[numericalfeatures])
        else:
            scalednumerical=self.scaler.transform(data[numericalfeatures])
        
        return np.hstack((encodedcategorical,scalednumerical))

    def trainmodel(self):
        print("Training ensemble model...")
        X=self.dataset[self.selectedfeatures]
        y=self.dataset["classnum"]
        X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=0.3,random_state=42)
        X_train_preprocessed=self.preprocessdata(X_train,training=True)
        X_test_preprocessed=self.preprocessdata(X_test,training=False)
        X_train_cnn=X_train_preprocessed.reshape(X_train_preprocessed.shape[0],X_train_preprocessed.shape[1],1)
        X_test_cnn=X_test_preprocessed.reshape(X_test_preprocessed.shape[0],X_test_preprocessed.shape[1],1)

        for name,model in self.models.items():
            if name=="cnn ":
                model.fit(X_train_cnn,y_train,epochs=10,batch_size=32,verbose=1)
                y_pred=(model.predict(X_test_cnn)>0.5).astype("int32")
            else:
                model.fit(X_train_preprocessed,y_train)
                y_pred=model.predict(X_test_preprocessed)
            accuracy=accuracy_score(y_test,y_pred)
            print(f"{name} Model Accuracy: {accuracy:.4f}")
        
        self.ensemble=VotingClassifier(
            estimators=[(name,model) for name,model in self.models.items() if name!="cnn"],
            voting='soft'
        )
        self.ensemble.fit(X_train_preprocessed,y_train)
        ensemble_predictions=self.ensemble.predict(X_test_preprocessed)
        ensemble_accuracy=accuracy_score(y_test,ensemble_predictions)
        print(f"Ensemble Model Accuracy: {ensemble_accuracy:.4f}")

    def predict(self,packet):
        packet_df=pd.DataFrame([packet])
        print("PacketDF:\n",packet_df)
        X_preprocessed=self.preprocessdata(packet_df,training=False)
        X_cnn=X_preprocessed.reshape(1,X_preprocessed.shape[0],1)
        cnn_prediction=(self.models["cnn"].predict(X_cnn)>0.5).astype("int32")[0][0]
        ensemble_prediction=self.ensemble.predict(X_preprocessed)
        
        return "anomaly" if ensemble_prediction[0]=="anomaly" else cnn_prediction

    def retrainfrombuffer(self):
        if self.buffer.empty:
            print("No new data for retraining.")
            return
        
        print("Retraining model with buffered data...")
        self.dataset=pd.concat([self.dataset,self.buffer],ignore_index=True)
        self.buffer=self.buffer.iloc[0:0]  
        self.trainmodel()

cloud_server=CloudServer()

@app.route('/predict',methods=['POST'])
def predictpacket():
    packet=request.json
    print("Received: ",str(packet))
    prediction=cloud_server.predict(packet)
    
    if prediction=="anomaly":
        cloud_server.buffer=pd.concat([cloud_server.buffer,pd.DataFrame([packet])],ignore_index=True)
    
    return jsonify({"prediction":prediction})

def periodicretraining():
    while True:
        time.sleep(3600)
        cloud_server.retrainfrombuffer()

threading.Thread(target=periodicretraining,daemon=True).start()

@app.route('/status',methods=['GET'])
def displaystatus():
    model_status="Ready."  
    return render_template('status.html',status=model_status)

if __name__=='__main__':
    app.run(host='0.0.0.0',port=5000)