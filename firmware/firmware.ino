#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <SPI.h>
#include <MFRC522.h>
#include <ArduinoJson.h>

// --- WiFi & MQTT Configuration ---
const char* TEAM_ID       = "the_rock";
const char* WIFI_SSID     = "EdNet";
const char* WIFI_PASSWORD = "Huawei@123";
const char* MQTT_BROKER   = "157.173.101.159";
const int MQTT_PORT       = 1883;

// --- MQTT Topics ---
String BASE_TOPIC    = String("rfid/") + TEAM_ID + "/";
String STATUS_TOPIC  = BASE_TOPIC + "card/status";
String TOPUP_TOPIC   = BASE_TOPIC + "card/topup";
String BALANCE_TOPIC = BASE_TOPIC + "card/balance";

// --- Pins (NodeMCU ESP8266) ---
const int RST_PIN = D1; 
const int SS_PIN  = D2; 

WiFiClient espClient;
PubSubClient client(espClient);
MFRC522 mfrc522(SS_PIN, RST_PIN);

// --- Memory-Based Balance Tracking ---
struct CardBalance {
  String uid;
  uint32_t balance;
};
CardBalance cards[20];
int cardCount = 0;

void setup_wifi() {
  delay(10);
  Serial.printf("\n[DEBUG] Connecting to WiFi: %s\n", WIFI_SSID);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  int counter = 0;
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
    if (++counter > 40) { // 20 seconds timeout
      Serial.println("\n[ERROR] WiFi Connection Timeout! Check SSID/Password or Signal.");
      counter = 0;
    }
  }

  Serial.println("\n[DEBUG] WiFi connected!");
  Serial.print("[DEBUG] IP address: ");
  Serial.println(WiFi.localIP());
}

void callback(char* topic, byte* payload, unsigned int length) {
  Serial.printf("\n[DEBUG] MQTT Message Arrival -> Topic: %s\n", topic);
  
  StaticJsonDocument<256> doc;
  DeserializationError error = deserializeJson(doc, payload, length);

  if (error) {
    Serial.printf("[ERROR] JSON Parse Failed: %s\n", error.c_str());
    return;
  }

  const char* target_uid = doc["uid"];
  uint32_t amount = doc["amount"];
  Serial.printf("[DEBUG] Command -> UID: %s, Amount: %u\n", target_uid, amount);

  for (int i = 0; i < cardCount; i++) {
    if (cards[i].uid == String(target_uid)) {
      cards[i].balance += amount;
      Serial.printf("[DEBUG] Balance Updated for %s -> New: %u\n", target_uid, cards[i].balance);
      
      StaticJsonDocument<128> out;
      out["uid"] = cards[i].uid;
      out["new_balance"] = cards[i].balance;
      char buffer[128];
      serializeJson(out, buffer);
      client.publish(BALANCE_TOPIC.c_str(), buffer);
      return;
    }
  }
}

void reconnect() {
  while (!client.connected()) {
    Serial.printf("[DEBUG] Connecting to MQTT Broker: %s:%d\n", MQTT_BROKER, MQTT_PORT);
    String clientId = "esp8266_the_rock_" + String(ESP.getChipId(), HEX);
    
    if (client.connect(clientId.c_str())) {
      Serial.println("[DEBUG] MQTT Connected!");
      client.subscribe(TOPUP_TOPIC.c_str());
      Serial.printf("[DEBUG] Subscribed to: %s\n", TOPUP_TOPIC.c_str());
    } else {
      Serial.printf("[ERROR] MQTT Failed, rc=%d. Retrying in 5s...\n", client.state());
      delay(5000);
    }
  }
}

void setup() {
  Serial.begin(115200);
  Serial.println("\n\n====================================");
  Serial.println("   EMERALD WALLET DEBUG START      ");
  Serial.println("====================================");
  
  SPI.begin();
  mfrc522.PCD_Init();
  
  byte v = mfrc522.PCD_ReadRegister(mfrc522.VersionReg);
  Serial.printf("[DEBUG] RC522 Version: 0x%02X\n", v);
  if (v == 0x00 || v == 0xFF) {
    Serial.println("[ERROR] RC522 Communication Failed! Check Wiring (D1, D2, D5, D6, D7).");
  }

  setup_wifi();
  client.setServer(MQTT_BROKER, MQTT_PORT);
  client.setCallback(callback);
}

void loop() {
  if (!client.connected()) reconnect();
  client.loop();

  if (!mfrc522.PICC_IsNewCardPresent()) return;
  if (!mfrc522.PICC_ReadCardSerial()) return;

  Serial.println("\n[DEBUG] RFID Tag Detected!");
  
  String uid_str = "";
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    uid_str += String(mfrc522.uid.uidByte[i] < 0x10 ? "0" : "");
    uid_str += String(mfrc522.uid.uidByte[i], HEX);
  }
  uid_str.toUpperCase();
  Serial.printf("[DEBUG] UID: %s\n", uid_str.c_str());

  uint32_t current_balance = 0;
  bool known = false;
  for (int i = 0; i < cardCount; i++) {
    if (cards[i].uid == uid_str) {
      current_balance = cards[i].balance;
      known = true;
      break;
    }
  }

  if (!known && cardCount < 20) {
    cards[cardCount].uid = uid_str;
    cards[cardCount].balance = 0;
    cardCount++;
    Serial.println("[DEBUG] New Card Registered In Memory.");
  }

  Serial.printf("[DEBUG] Current Balance: %u. Publishing Status...\n", current_balance);
  
  StaticJsonDocument<128> statusDoc;
  statusDoc["uid"] = uid_str;
  statusDoc["balance"] = current_balance;
  char statusBuffer[128];
  serializeJson(statusDoc, statusBuffer);
  
  if (client.publish(STATUS_TOPIC.c_str(), statusBuffer)) {
    Serial.println("[DEBUG] Status Published Successfully.");
  } else {
    Serial.println("[ERROR] Status Publish Failed!");
  }

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  delay(1000);
}