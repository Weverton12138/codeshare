const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { User, ChatMessage, Report, sanitizeInput } = require('./backend_nodejs_server');

const chatLimiter = new Map();

const checkChatRateLimit = (userId) => {
    const now = Date.now();
    const userLimits = chatLimiter.get(userId) || { count: 0, resetTime: now + 60000 };
    
    if (now > userLimits.resetTime) {
        userLimits.count = 0;
        userLimits.resetTime = now + 60000;
    }
    
    if (userLimits.count >= 30) {
        return false;
    }
    
    userLimits.count++;
    chatLimiter.set(userId, userLimits);
    return true;
};

const bannedWords = [
    'spam', 'hack malicioso', 'vírus', 'trojan', 'keylogger',
    'roubar senha', 'cartão de crédito', 'phishing', 'scam'
];

const containsBannedWords = (message) => {
    const lowerMessage = message.toLowerCase();
    return bannedWords.some(word => lowerMessage.includes(word));
};

const messageHistory = new Map();

const checkFlood = (userId, message) => {
    const now = Date.now();
    const userHistory = messageHistory.get(userId) || [];
    const recentMessages = userHistory.filter(msg => now - msg.timestamp < 30000);
    
    const duplicateMessage = recentMessages.find(msg => msg.content === message);
    if (duplicateMessage) {
        return false;
    }
    
    if (recentMessages.length >= 5) {
        return false;
    }
    
    recentMessages.push({ content: message, timestamp: now });
    messageHistory.set(userId, recentMessages);
    return true;
};

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

const setupChatSocket = (io) => {
    io.use(authenticateSocket);
    
    const chatStats = {
        onlineUsers: new Set(),
        totalMessages: 0,
        bannedUsers: new Set()
    };
    
    io.on('connection', async (socket) => {
        try {
            console.log(`👤 Usuário ${socket.username} conectado ao chat`);
            chatStats.onlineUsers.add(socket.userId.toString());
            socket.join('main-chat');
            io.emit('chat_stats', { online: chatStats.onlineUsers.size, totalMessages: chatStats.totalMessages });

            const recentMessages = await ChatMessage.find({ isDeleted: false })
                .populate('user', 'username reputation')
                .sort({ createdAt: -1 })
                .limit(50);
            socket.emit('chat_history', recentMessages.reverse());

            socket.on('send_message', async (payload) => {
                try {
                    const text = (typeof payload === 'string') ? payload : payload?.message;
                    if (!text || !text.trim()) return socket.emit('error_message', 'Mensagem vazia');

                    if (!checkChatRateLimit(socket.userId)) return socket.emit('error_message', 'Limite de mensagens por minuto atingido');
                    if (!checkFlood(socket.userId, text)) return socket.emit('error_message', 'Envio duplicado ou muito rápido');
                    if (containsBannedWords(text)) return socket.emit('error_message', 'Mensagem contém palavras proibidas');

                    const cleanText = sanitizeInput(text);
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

            socket.on('edit_message', async ({ messageId, newText }) => {
                try {
                    if (!messageId || !newText) return;
                    const msg = await ChatMessage.findById(messageId);
                    if (!msg) return;

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