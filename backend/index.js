// Salvar como: C:\Users\Everton\codeshare\backend\index.js
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Servir arquivos estáticos do frontend
app.use(express.static(path.join(__dirname, '../frontend')));

// CONEXÃO MONGODB CORRIGIDA - PORTA 27017!
const MONGODB_URI = 'mongodb://127.0.0.1:27017/codeshare';

console.log('🔄 Conectando ao MongoDB...');
mongoose.connect(MONGODB_URI)
    .then(() => {
        console.log('✅ MongoDB conectado com sucesso na porta 27017!');
    })
    .catch((err) => {
        console.error('❌ Erro ao conectar ao MongoDB:', err);
        process.exit(1);
    });

// Schemas básicos
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

// Rotas básicas
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/software_sharing_platform.html'));
});

// API de teste
app.get('/api/test', (req, res) => {
    res.json({ 
        message: 'CodeShare API funcionando!', 
        mongodb: 'Conectado',
        timestamp: new Date().toISOString()
    });
});

// WebSocket para chat
io.on('connection', (socket) => {
    console.log('👤 Usuário conectado:', socket.id);
    
    socket.on('join-chat', (data) => {
        socket.join('general');
        socket.broadcast.to('general').emit('user-joined', {
            message: `${data.username} entrou no chat`,
            timestamp: new Date().toISOString()
        });
    });
    
    socket.on('chat-message', (data) => {
        io.to('general').emit('message', {
            username: data.username,
            message: data.message,
            timestamp: new Date().toISOString()
        });
    });
    
    socket.on('disconnect', () => {
        console.log('👤 Usuário desconectado:', socket.id);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Servidor CodeShare rodando na porta ${PORT}`);
    console.log(`📱 Acesse: http://localhost:${PORT}`);
    console.log(`🔍 API Test: http://localhost:${PORT}/api/test`);
});

module.exports = { app, server, io, User, Software };