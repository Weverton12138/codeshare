// websocket_chat_system.js - Sistema de Chat em Tempo Real com Socket.io
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

// Importar modelos do servidor principal (aponta pro seu backend real)
const { User, ChatMessage, Report, sanitizeInput } = require('./backend_nodejs_server');

// Rate limiting para chat (map por usuário)
const chatLimiter = new Map();

const checkChatRateLimit = (userId) => {
    const now = Date.now();
    const userLimits = chatLimiter.get(userId) || { count: 0, resetTime: now + 60000 };
    
    if (now > userLimits.resetTime) {
        userLimits.count = 0;
        userLimits.resetTime = now + 60000; // reset a cada minuto
    }
    
    if (userLimits.count >= 30) { // Máximo 30 mensagens por minuto
        return false;
    }
    
    userLimits.count++;
    chatLimiter.set(userId, userLimits);
    return true;
};

// Lista de palavras proibidas (anti-spam básico)
const bannedWords = [
    'spam', 'hack malicioso', 'vírus', 'trojan', 'keylogger',
    'roubar senha', 'cartão de crédito', 'phishing', 'scam'
];

const containsBannedWords = (message) => {
    const lowerMessage = message.toLowerCase();
    return bannedWords.some(word => lowerMessage.includes(word));
};

// Sistema anti-flood
const messageHistory = new Map();

const checkFlood = (userId, message) => {
    const now = Date.now();
    const userHistory = messageHistory.get(userId) || [];
    
    // Remove mensagens antigas (últimos 30 segundos)
    const recentMessages = userHistory.filter(msg => now - msg.timestamp < 30000);
    
    // Verifica se enviou a mesma mensagem recentemente
    const duplicateMessage = recentMessages.find(msg => msg.content === message);
    if (duplicateMessage) {
        return false;
    }
    
    // Verifica se enviou muitas mensagens muito rápido
    if (recentMessages.length >= 5) { // Máximo 5 mensagens em 30 segundos
        return false;
    }
    
    recentMessages.push({ content: message, timestamp: now });
    messageHistory.set(userId, recentMessages);
    return true;
};

// Middleware de autenticação para Socket.io
const authenticateSocket = async (socket, next) => {
    try {
        const token = socket.handshake.auth?.token || socket.handshake.query?.token;
        if (!token) {
            return next(new Error('Token de autenticação necessário'));
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'codeshare_secret_key');
        const user = await User.findById(decoded.userId);
        
        if (!user) {
            return next(new Error('Usuário não encontrado'));
        }
        
        if (user.isBanned) {
            return next(new Error('Usuário banido'));
        }
        
        socket.userId = user._id;
        socket.username = user.username;
        socket.isAdmin = user.isAdmin;
        socket.reputation = user.reputation;
        
        next();
    } catch (error) {
        next(new Error('Token inválido'));
    }
};

// Configuração do Socket.io para Chat
const setupChatSocket = (io) => {
    // Middleware de autenticação
    io.use(authenticateSocket);
    
    // Estatísticas do chat
    const chatStats = {
        onlineUsers: new Set(),
        totalMessages: 0,
        bannedUsers: new Set()
    };
    
    io.on('connection', async (socket) => {
        try {
            console.log(`👤 Usuário ${socket.username} conectado ao chat`);
            
            // Adicionar usuário online
            chatStats.onlineUsers.add(socket.userId.toString());
            
            // Entrar na sala principal
            socket.join('main-chat');

            // Emit online count
            io.emit('chat_stats', { online: chatStats.onlineUsers.size, totalMessages: chatStats.totalMessages });

            // Enviar histórico de mensagens recentes
            try {
                const recentMessages = await ChatMessage.find({ isDeleted: false })
                    .populate('user', 'username reputation')
                    .sort({ createdAt: -1 })
                    .limit(50);
                // enviar em ordem cronológica
                socket.emit('chat_history', recentMessages.reverse());
            } catch (err) {
                console.error('Erro ao buscar histórico do chat:', err);
            }

            // Evento: enviar mensagem
            socket.on('send_message', async (payload) => {
                try {
                    const text = (typeof payload === 'string') ? payload : payload?.message;
                    if (!text || !text.trim()) return socket.emit('error_message', 'Mensagem vazia');

                    // rate limit e flood
                    if (!checkChatRateLimit(socket.userId)) return socket.emit('error_message', 'Limite de mensagens por minuto atingido');
                    if (!checkFlood(socket.userId, text)) return socket.emit('error_message', 'Envio duplicado ou muito rápido');

                    // palavras proibidas
                    if (containsBannedWords(text)) return socket.emit('error_message', 'Mensagem contém palavras proibidas');

                    // sanitizar
                    const cleanText = sanitizeInput(text);

                    // criar e salvar
                    const messageDoc = new ChatMessage({
                        user: socket.userId,
                        username: socket.username,
                        message: cleanText
                    });
                    await messageDoc.save();

                    chatStats.totalMessages++;

                    const broadcastMsg = {
                        id: messageDoc._id,
                        user: { id: socket.userId, username: socket.username, reputation: socket.reputation },
                        message: cleanText,
                        createdAt: messageDoc.createdAt
                    };

                    io.to('main-chat').emit('new_message', broadcastMsg);
                    io.emit('chat_stats', { online: chatStats.onlineUsers.size, totalMessages: chatStats.totalMessages });

                } catch (err) {
                    console.error('Erro ao processar send_message:', err);
                    socket.emit('error_message', 'Erro ao enviar mensagem');
                }
            });

            // Evento: deletar mensagem (só admin)
            socket.on('delete_message', async (messageId) => {
                try {
                    if (!socket.isAdmin) return socket.emit('error_message', 'Permissão negada');
                    if (!messageId) return;

                    await ChatMessage.findByIdAndUpdate(messageId, { isDeleted: true });
                    io.to('main-chat').emit('message_deleted', messageId);
                } catch (err) {
                    console.error('Erro ao deletar mensagem:', err);
                }
            });

            // Evento: reportar mensagem
            socket.on('report_message', async ({ messageId, reason }) => {
                try {
                    if (!messageId || !reason) return socket.emit('error_message', 'Dados inválidos');
                    const report = new Report({
                        reporter: socket.userId,
                        target: messageId,
                        targetType: 'message',
                        reason,
                        description: ''
                    });
                    await report.save();
                    socket.emit('report_submitted', { ok: true });
                } catch (err) {
                    console.error('Erro ao reportar mensagem:', err);
                }
            });

            // Evento: editar mensagem (autor ou admin)
            socket.on('edit_message', async ({ messageId, newText }) => {
                try {
                    if (!messageId || !newText) return;
                    const msg = await ChatMessage.findById(messageId);
                    if (!msg) return;

                    // só autor ou admin pode editar
                    if (msg.user.toString() !== socket.userId.toString() && !socket.isAdmin) {
                        return socket.emit('error_message', 'Permissão negada para editar');
                    }

                    if (!checkChatRateLimit(socket.userId)) return socket.emit('error_message', 'Limite de ações atingido');

                    if (containsBannedWords(newText)) return socket.emit('error_message', 'Texto contém palavras proibidas');

                    const cleanText = sanitizeInput(newText);
                    msg.message = cleanText;
                    msg.updatedAt = new Date();
                    await msg.save();

                    io.to('main-chat').emit('message_edited', {
                        id: msg._id,
                        message: cleanText,
                        updatedAt: msg.updatedAt
                    });

                } catch (err) {
                    console.error('Erro ao editar mensagem:', err);
                }
            });

            // Desconexão
            socket.on('disconnect', () => {
                chatStats.onlineUsers.delete(socket.userId.toString());
                io.emit('chat_stats', { online: chatStats.onlineUsers.size, totalMessages: chatStats.totalMessages });
                console.log(`❌ Usuário ${socket.username} desconectado`);
            });
        } catch (outerErr) {
            console.error('Erro na conexão do socket:', outerErr);
        }
    });
};

module.exports = setupChatSocket;
