# Emerald Wallet | RFID Ecosystem (Production)

This project is a high-performance RFID card top-up ecosystem. It features a NodeMCU Emerald Hub (Edge), a Remote Node.js API Bridge, and a real-time Web Dashboard.

## 🚀 Live Production URL
**Dashboard:** [http://157.173.101.159:9242/wallet.html](http://157.173.101.159:9242/wallet.html)

## System Architecture

1.  **Emerald Hub (NodeMCU ESP8266):** Scans RFID cards and tracks balances in a local memory array. It communicates via **MQTT** using the public broker `157.173.101.159`.
2.  **Backend Bridge (Node.js):** Hosted on a remote server. It bridges MQTT events to the Web Dashboard via **WebSockets** and provides a REST API for top-ups.
3.  **Web Dashboard:** A premium, real-time UI built with Tailwind CSS for monitoring scans and managing liquidity.

## Project Structure

-   `firmware/`: C++ Arduino code for the ESP8266.
    -   `firmware.ino`: Main logic for WiFi, MQTT, and memory-based balance tracking.
-   `server.js`: Node.js backend logic (deployed remotely).
-   `wallet.html`: Frontend dashboard (served by the backend).

## Technical Specifications

-   **WiFi Networking:** Connects via `EdNet` (WPA2).
-   **MQTT Broker:** Public Cloud IP `157.173.101.159` on Port `1883`.
-   **Balance Logic:** Memory-based (RAM). *Note: Balances reset if the hub is powered off.*
-   **Identity Protection:** Unique Client IDs generated using ESP Chip ID to prevent hotspot collisions.

## Hardware Wiring (NodeMCU to MFRC522)

| RC522 Pin | NodeMCU Pin |
| :--- | :--- |
| SDA (SS) | D2 |
| SCK | D5 |
| MOSI | D7 |
| MISO | D6 |
| RST | D1 |
| 3.3V | 3V3 |

## Deployment Guide

### Hardware
1.  Open `firmware/firmware.ino` in Arduino IDE.
2.  Install `PubSubClient`, `MFRC522`, and `ArduinoJson` libraries.
3.  Upload to your NodeMCU ESP8266.
4.  Open Serial Monitor (115200 baud) and confirm `[DEBUG] MQTT Connected!`.

### Git Workflow
To push updates to GitHub:
```bash
git add .
git commit -m "Update: Production deployment config"
git push origin main
```

## Team Member Customization (Forking)

If you are a member of **THE ROCK** and want to deploy this for yourself on your own server/GitHub, change these specific lines:

### 1. Firmware (`firmware/firmware.ino`)
-   **Line 8:** `TEAM_ID = "your_unique_name"` (Change this so you don't receive other people's scans!)
-   **Line 9 & 10:** Update `WIFI_SSID` and `WIFI_PASSWORD` for your local network.
-   **Line 11:** `MQTT_BROKER = "your_server_ip"` (The IP of your own cloud server).

### 2. Backend (`server.js`)
-   **Line 13:** `const MQTT_BROKER = 'your_server_ip';`
-   **Line 91:** `const PORT = your_port_number;`
-   **Line 92:** `server.listen(PORT, 'your_server_ip', ...)`

### 3. Dashboard (`wallet.html`)
-   **Line 268:** `const BACKEND_URL = "http://your_server_ip:your_port";`

### 4. GitHub
1.  Fork this repository or create a new one.
2.  Update the **Live Production URL** at the top of this `README.md` to point to your link.
3.  Commit and Push:
    ```bash
    git commit -m "Identity: Switched to [Your Name] infrastructure"
    git push origin main
    ```

## Features
-   ✅ Real-time "Emerald Stream" balance updates.
-   ✅ Unique Team Identity (`the_rock`).
-   ✅ High-visibility debug logging.
-   ✅ Premium Glassmorphism UI."# RFID-PAYMENT-SYSTEM" 
