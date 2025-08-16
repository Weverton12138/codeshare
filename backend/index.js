const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const setupChatSocket = require('./websocket_chat_system');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: { origin: process.env.FRONTEND_URL || "https://codeshare.onrender.com", methods: ["GET", "POST"] }
});

// Middleware
app.use(cors({ origin: process.env.FRONTEND_URL || "https://codeshare.onrender.com" }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Servir frontend
app.use(express.static(path.join(__dirname, '../frontend')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// Conexão MongoDB Atlas
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
    console.error('❌ MONGODB_URI não definido! Adicione no ambiente.');
    process.exit(1);
}

mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('✅ MongoDB Atlas conectado!'))
    .catch((err) => {
        console.error('❌ Erro ao conectar ao MongoDB Atlas:', err.message, err.stack);
        process.exit(1);
    });

// Schemas
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const softwareSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: String,
    category: String,
    license: String,
    tags: [String],
    filename: String,
    uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    downloads: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Software = mongoose.model('Software', softwareSchema);

// API de teste
app.get('/api/test', (req, res) => {
    res.json({ 
        message: 'CodeShare API funcionando!', 
        mongodb: 'Conectado',
        timestamp: new Date().toISOString()
    });
});

// Configurar chat
setupChatSocket(io);

// Porta dinâmica
const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
    console.log(`🚀 Servidor CodeShare rodando na porta ${PORT}`);
    console.log(`📱 Acesse: http://localhost:${PORT}`);
    console.log(`🔍 API Test: http://localhost:${PORT}/api/test`);
});