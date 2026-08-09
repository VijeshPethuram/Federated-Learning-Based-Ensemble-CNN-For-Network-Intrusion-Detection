#include <PulseSensorPlayground.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <mbedtls/md.h>

const int pulsePin=34;
const int threshold=550;

const char* wifiSsid="moto g32";
const char* wifiPassword="sriganesh";

const char* serverUrl="https://eids-hs.onrender.com/data";

const char* traUrl="http://localhost:6000";
const char* entityId="pulse_sensor_1";
String sessionKey;

PulseSensorPlayground pulseSensor;

void setup() {
  Serial.begin(115200);

  Serial.println("Connecting to Wi-Fi...");
  WiFi.begin(wifiSsid, wifiPassword);

  while(WiFi.status()!=WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWi-Fi connected!");

  pulseSensor.analogInput(pulsePin);
  pulseSensor.setThreshold(threshold);

  if(!pulseSensor.begin()) {
    Serial.println("Pulse Sensor initialization failed!");
    while(1);
  }

  Serial.println("Pulse Sensor initialized.");
  registerWithTra();
}

void loop() {
  if(pulseSensor.sawStartOfBeat()) {
    int bpm=pulseSensor.getBeatsPerMinute();

    Serial.print("Heartbeat detected! BPM: ");
    Serial.println(bpm);

    sendDataToServer(bpm);
  }

  delay(20);
}

void registerWithTra() {
  if(WiFi.status()==WL_CONNECTED) {
    HTTPClient http;
    http.begin(String(traUrl)+"/register");
    http.addHeader("Content-Type", "application/json");

    String payload="{";
    payload+="\"entity_id\": \""+String(entityId)+"\", ";
    payload+="\"entity_type\": \"pulse_sensor\"";
    payload+="}";

    int httpResponseCode=http.POST(payload);

    if(httpResponseCode==201) {
      String response=http.getString();
      DynamicJsonDocument doc(1024);
      deserializeJson(doc, response);
      sessionKey=doc["session_key"].as<String>();
      Serial.println("Successfully registered with TRA. SKEY: "+sessionKey);
    } else {
      Serial.println("TRA registration failed: "+String(httpResponseCode));
    }

    http.end();
  } else {
    Serial.println("Wi-Fi not connected!");
  }
}

String generateHmac(String message) {
  byte hmacResult[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t mdType=MBEDTLS_MD_SHA256;
  const size_t keyLength=sessionKey.length();

  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(mdType), 1);
  mbedtls_md_hmac_starts(&ctx, (unsigned char*)sessionKey.c_str(), keyLength);
  mbedtls_md_hmac_update(&ctx, (unsigned char*)message.c_str(), message.length());
  mbedtls_md_hmac_finish(&ctx, hmacResult);
  mbedtls_md_free(&ctx);

  String hmacStr="";
  for(int i=0; i<sizeof(hmacResult); i++) {
    char str[3];
    sprintf(str, "%02x", (unsigned int)hmacResult[i]);
    hmacStr+=str;
  }
  return hmacStr;
}

void sendDataToServer(int bpm) {
  if(WiFi.status()==WL_CONNECTED) {
    HTTPClient http;
    http.begin(serverUrl);
    http.addHeader("Content-Type", "application/json");

    String nonce=String(random(0, 999999));
    String hmac=generateHmac(nonce);

    http.addHeader("Entity-ID", entityId);
    http.addHeader("Nonce", nonce);
    http.addHeader("HMAC", hmac);

    String payload="{";
    payload+="\"id\": \"sensor1\", ";
    payload+="\"bpm\": "+String(bpm);
    payload+="}";

    int httpResponseCode=http.POST(payload);

    if(httpResponseCode>0) {
      String response=http.getString();
      Serial.println("Server response: "+response);
    } else {
      Serial.println("Error in sending POST request: "+String(httpResponseCode));
    }

    http.end();
  } else {
    Serial.println("Wi-Fi not connected!");
  }
}