const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const mqtt = require('mqtt');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// === YOUR CONFIG ===
const TEAM_ID = 'the_rock';
const MQTT_BROKER = '157.173.101.159';
const MQTT_PORT = 1883;

const BASE_TOPIC = `rfid/${TEAM_ID}`;
const STATUS_TOPIC = `${BASE_TOPIC}/card/status`;
const BALANCE_TOPIC = `${BASE_TOPIC}/card/balance`;
const TOPUP_TOPIC = `${BASE_TOPIC}/card/topup`;

// MQTT Client
const mqttClient = mqtt.connect(`mqtt://${MQTT_BROKER}:${MQTT_PORT}`, {
    clientId: `backend_${TEAM_ID}_${Math.random().toString(16).slice(3)}`
});

mqttClient.on('connect', () => {
    console.log('--- DEBUG: MQTT connected to broker ---');
    mqttClient.subscribe([STATUS_TOPIC, BALANCE_TOPIC], (err) => {
        if (!err) {
            console.log(`--- DEBUG: Subscribed to ${STATUS_TOPIC} and ${BALANCE_TOPIC} ---`);
        } else {
            console.error('--- DEBUG: Subscription Error:', err);
        }
    });
});

mqttClient.on('message', (topic, message) => {
    console.log(`--- DEBUG: MQTT Message Received on [${topic}] ---`);
    try {
        const payload = JSON.parse(message.toString());
        console.log('--- DEBUG: Payload:', JSON.stringify(payload, null, 2));

        // Broadcast to all connected WebSocket clients
        let clientCount = 0;
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({ topic, data: payload }));
                clientCount++;
            }
        });
        console.log(`--- DEBUG: Broadcasted to ${clientCount} dashboard(s) ---`);
    } catch (e) {
        console.error('--- DEBUG: Invalid JSON Received:', message.toString());
    }
});

mqttClient.on('error', (err) => console.error('--- DEBUG: MQTT ERROR:', err));

// HTTP middleware
app.use(express.json());

// Serve frontend static files
app.use(express.static(__dirname));

// POST /topup - from dashboard
app.post('/topup', (req, res) => {
    console.log('--- DEBUG: POST /topup received ---');
    const { uid, amount } = req.body;
    console.log('--- DEBUG: Topup Data:', { uid, amount });

    if (!uid || typeof amount !== 'number' || amount <= 0) {
        console.error('--- DEBUG: Topup Validation Failed ---');
        return res.status(400).json({ error: 'Invalid uid or amount (>0)' });
    }

    const payload = JSON.stringify({ uid, amount });
    mqttClient.publish(TOPUP_TOPIC, payload);
    console.log(`--- DEBUG: Published to ${TOPUP_TOPIC} ---`);

    res.json({ success: true, message: 'Top-up command sent' });
});

// WebSocket connection
wss.on('connection', (ws) => {
    console.log('--- DEBUG: New Dashboard WebSocket Connection Established ---');
    ws.send(JSON.stringify({ message: 'Connected to real-time updates' }));

    ws.on('close', () => console.log('--- DEBUG: Dashboard WebSocket Disconnected ---'));
});

const PORT = 9242;
server.listen(PORT, '157.173.101.159', () => {
    console.log('============================================');
    console.log(`Backend running on http://157.173.101.159:${PORT}/wallet.html`);
    console.log('Waiting for RFID scans...');
    console.log('============================================');
});
