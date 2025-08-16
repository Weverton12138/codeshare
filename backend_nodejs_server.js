const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const xss = require('xss');
const setupChatSocket = require('./websocket_chat_system');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: { origin: process.env.FRONTEND_URL || "https://codeshare.onrender.com", methods: ["GET", "POST"] }
});

// ============================
// Segurança e Middleware
// ============================
app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL || "https://codeshare.onrender.com" }));
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// Serve frontend
app.use(express.static(path.join(__dirname, '../frontend')));
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend', 'index.html'));
});

// Rate limit
const limiter = rateLimit({ windowMs: 15*60*1000, max: 100, message: { error: 'Muitas tentativas. Tente novamente em 15 minutos.', code: 'RATE_LIMIT_EXCEEDED' } });
const uploadLimiter = rateLimit({ windowMs: 60*60*1000, max: 10, message: { error: 'Limite de uploads excedido. Tente novamente em 1 hora.', code: 'UPLOAD_LIMIT_EXCEEDED' } });
app.use(limiter);

// ============================
// Conexão MongoDB (Apenas Atlas)
// ============================
const mongoURI = process.env.MONGODB_URI;
if (!mongoURI) {
    console.error('❌ MONGODB_URI não definido! Adicione no ambiente.');
    process.exit(1);
}

mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('✅ Conectado ao MongoDB Atlas'))
    .catch(err => {
        console.error('❌ Erro ao conectar ao MongoDB:', err.message, err.stack);
        process.exit(1);
    });

// ============================
// Schemas
// ============================
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, maxlength: 30 },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, minlength: 6 },
    avatar: { type: String, default: '' },
    reputation: { type: Number, default: 0 },
    isAdmin: { type: Boolean, default: false },
    isBanned: { type: Boolean, default: false },
    uploadCount: { type: Number, default: 0 },
    downloadCount: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    lastActive: { type: Date, default: Date.now }
});

const SoftwareSchema = new mongoose.Schema({
    title: { type: String, required: true, maxlength: 100 },
    description: { type: String, required: true, maxlength: 2000 },
    category: { type: String, required: true, enum: ['pc-utilities','pc-games','pc-security','android-social','android-games','android-modified','script-python','script-javascript','script-batch','script-powershell'] },
    tags: [{ type: String, maxlength: 20 }],
    license: { type: String, required: true, enum: ['free','open-source','shareware','modified'] },
    filename: { type: String, required: true },
    originalName: { type: String, required: true },
    fileSize: { type: Number, required: true },
    fileType: { type: String, required: true },
    filePath: { type: String, required: true },
    hash: { type: String, required: true },
    virusScanResult: {
        scanned: { type: Boolean, default: false },
        clean: { type: Boolean, default: false },
        scanDate: { type: Date },
        threats: [String]
    },
    uploader: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    downloads: { type: Number, default: 0 },
    rating: { type: Number, default: 0 },
    ratingCount: { type: Number, default: 0 },
    isApproved: { type: Boolean, default: false },
    isReported: { type: Boolean, default: false },
    reportCount: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const ReviewSchema = new mongoose.Schema({
    software: { type: mongoose.Schema.Types.ObjectId, ref: 'Software', required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    rating: { type: Number, required: true, min: 1, max: 5 },
    comment: { type: String, maxlength: 500 },
    isReported: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const ChatMessageSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    username: { type: String, required: true },
    message: { type: String, required: true, maxlength: 500 },
    isDeleted: { type: Boolean, default: false },
    isReported: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const ReportSchema = new mongoose.Schema({
    reporter: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    target: { type: mongoose.Schema.Types.ObjectId, required: true },
    targetType: { type: String, required: true, enum: ['software','review','message','user'] },
    reason: { type: String, required: true, enum: ['spam','malware','inappropriate','copyright','fake','abuse'] },
    description: { type: String, maxlength: 500 },
    status: { type: String, default: 'pending', enum: ['pending','resolved','dismissed'] },
    createdAt: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', UserSchema);
const Software = mongoose.model('Software', SoftwareSchema);
const Review = mongoose.model('Review', ReviewSchema);
const ChatMessage = mongoose.model('ChatMessage', ChatMessageSchema);
const Report = mongoose.model('Report', ReportSchema);

// ============================
// Multer Upload
// ============================
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'uploads/software/');
        if (!fs.existsSync(uploadPath)) fs.mkdirSync(uploadPath, { recursive: true });
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + Math.round(Math.random()*1E9) + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = ['.exe','.apk','.py','.js','.zip','.rar','.7z','.bat','.ps1','.sh'];
    const fileExt = path.extname(file.originalname).toLowerCase();
    cb(allowedTypes.includes(fileExt) ? null : new Error('Tipo de arquivo não suportado'), allowedTypes.includes(fileExt));
};

const upload = multer({ storage, fileFilter, limits: { fileSize: 500*1024*1024 } });

// ============================
// Middlewares
// ============================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token de acesso requerido' });
    jwt.verify(token, process.env.JWT_SECRET || 'codeshare_secret_key', (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido' });
        req.user = user;
        next();
    });
};

const checkBanned = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.userId);
        if (user.isBanned) return res.status(403).json({ error: 'Usuário banido' });
        next();
    } catch (e) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
};

const sanitizeInput = input => validator.escape(xss(input.trim()));
const getFileHash = filePath => crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');

// ============================
// Rotas
// ============================
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const sanitizedUsername = sanitizeInput(username);
        const sanitizedEmail = sanitizeInput(email);
        if (!validator.isEmail(sanitizedEmail)) {
            return res.status(400).json({ error: 'Email inválido' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            username: sanitizedUsername,
            email: sanitizedEmail,
            password: hashedPassword
        });
        await user.save();
        res.status(201).json({ message: 'Usuário registrado com sucesso' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: sanitizeInput(email) });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'codeshare_secret_key', { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/test', authenticateToken, (req, res) => {
    res.json({ message: 'API protegida funcionando!', userId: req.user.userId });
});

app.post('/api/upload', authenticateToken, checkBanned, uploadLimiter, upload.single('file'), async (req, res) => {
    try {
        const file = req.file;
        if (!file) return res.status(400).json({ error: 'Nenhum arquivo enviado' });
        const software = new Software({
            title: sanitizeInput(req.body.title),
            description: sanitizeInput(req.body.description),
            category: req.body.category,
            license: req.body.license,
            tags: req.body.tags ? req.body.tags.map(sanitizeInput) : [],
            filename: file.filename,
            originalName: file.originalname,
            fileSize: file.size,
            fileType: path.extname(file.originalname),
            filePath: file.path,
            hash: getFileHash(file.path),
            uploader: req.user.userId
        });
        await software.save();
        res.json({ message: 'Arquivo enviado com sucesso' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================
// Chat Socket
// ============================
setupChatSocket(io);

// ============================
// Iniciar Servidor
// ============================
const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
    console.log(`🚀 Servidor CodeShare rodando na porta ${PORT}`);
    console.log(`📱 Acesse: http://localhost:${PORT}`);
    console.log(`🔍 API Test: http://localhost:${PORT}/api/test`);
});

// Exportar para uso em outros módulos
module.exports = { app, server, io, User, Software, Review, ChatMessage, Report, authenticateToken, checkBanned, sanitizeInput };