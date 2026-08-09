#include <PulseSensorPlayground.h>
#include <WiFi.h>
#include <HTTPClient.h>

const int PulsePin = 34; 
const int Threshold = 550; 

const char* ssid = "motog32"; 
const char* password = "sriganesh"; 

const char* serverURL = "https://esp-server-ze37.onrender.com/data"; 

PulseSensorPlayground pulseSensor;

void setup() {
  Serial.begin(115200);

  Serial.println("Connecting to Wi-Fi...");
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWi-Fi connected!");

  pulseSensor.analogInput(PulsePin);
  pulseSensor.setThreshold(Threshold);

  if (!pulseSensor.begin()) {
    Serial.println("Pulse Sensor initialization failed!");
    while (1); 
  }

  Serial.println("Pulse Sensor initialized.");
}

void loop() {
  if (pulseSensor.sawStartOfBeat()) {
    int bpm = pulseSensor.getBeatsPerMinute();

    Serial.print("Heartbeat detected! BPM: ");
    Serial.println(bpm);

    sendDataToServer(bpm);
  }

  delay(20);
}

void sendDataToServer(int bpm) {
  if (WiFi.status() == WL_CONNECTED) {
    HTTPClient http;
    http.begin(serverURL);
    http.addHeader("Content-Type", "application/json");

    String payload = "{";
    payload += "\"id\": \"sensor1\", ";
    payload += "\"bpm\": " + String(bpm);
    payload += "}";

    int httpResponseCode = http.POST(payload);

    if (httpResponseCode > 0) {
      String response = http.getString();
      Serial.println("Server response: " + response);
    } else {
      Serial.println("Error in sending POST request: " + String(httpResponseCode));
    }

    http.end(); 
  } else {
    Serial.println("Wi-Fi not connected!");
  }
}
