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
const helmet = require('helmet');
const validator = require('validator');
const xss = require('xss');
const ClamScan = require('clamscan');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Configurações de segurança
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// Serve frontend static files
app.use(express.static(path.join(__dirname, '../frontend')));
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend', 'software_sharing_platform.html'));
});

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // máximo 100 requests por IP
    message: {
        error: 'Muitas tentativas. Tente novamente em 15 minutos.',
        code: 'RATE_LIMIT_EXCEEDED'
    }
});

const uploadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hora
    max: 10, // máximo 10 uploads por hora
    message: {
        error: 'Limite de uploads excedido. Tente novamente em 1 hora.',
        code: 'UPLOAD_LIMIT_EXCEEDED'
    }
});

app.use(limiter);

// Configuração do MongoDB
mongoose.connect('mongodb://localhost:3000/codeshare');

// Schemas do MongoDB
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
    category: { 
        type: String, 
        required: true,
        enum: ['pc-utilities', 'pc-games', 'pc-security', 'android-social', 
               'android-games', 'android-modified', 'script-python', 
               'script-javascript', 'script-batch', 'script-powershell']
    },
    tags: [{ type: String, maxlength: 20 }],
    license: { 
        type: String, 
        required: true,
        enum: ['free', 'open-source', 'shareware', 'modified']
    },
    filename: { type: String, required: true },
    originalName: { type: String, required: true },
    fileSize: { type: Number, required: true },
    fileType: { type: String, required: true },
    filePath: { type: String, required: true },
    hash: { type: String, required: true }, // SHA-256 hash do arquivo
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
    targetType: { type: String, required: true, enum: ['software', 'review', 'message', 'user'] },
    reason: { 
        type: String, 
        required: true,
        enum: ['spam', 'malware', 'inappropriate', 'copyright', 'fake', 'abuse']
    },
    description: { type: String, maxlength: 500 },
    status: { type: String, default: 'pending', enum: ['pending', 'resolved', 'dismissed'] },
    createdAt: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', UserSchema);
const Software = mongoose.model('Software', SoftwareSchema);
const Review = mongoose.model('Review', ReviewSchema);
const ChatMessage = mongoose.model('ChatMessage', ChatMessageSchema);
const Report = mongoose.model('Report', ReportSchema);

// Configuração do Multer para upload de arquivos
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'uploads/software/');
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = ['.exe', '.apk', '.py', '.js', '.zip', '.rar', '.7z', '.bat', '.ps1', '.sh'];
    const fileExt = path.extname(file.originalname).toLowerCase();
    
    if (allowedTypes.includes(fileExt)) {
        cb(null, true);
    } else {
        cb(new Error('Tipo de arquivo não suportado'), false);
    }
};

const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 500 * 1024 * 1024, // 500MB max
    }
});

// Inicialização do ClamAV
let clamscan;
(async () => {
    try {
        // Create logs and quarantine directories
        const logPath = path.join(__dirname, 'logs');
        const quarantinePath = path.join(__dirname, 'quarantine');
        if (!fs.existsSync(logPath)) {
            fs.mkdirSync(logPath, { recursive: true });
        }
        if (!fs.existsSync(quarantinePath)) {
            fs.mkdirSync(quarantinePath, { recursive: true });
        }

        clamscan = await new ClamScan().init({
            removeInfected: true,
            quarantineInfected: quarantinePath,
            scanLog: path.join(logPath, 'scan.log'),
            debugMode: true,
            fileList: null,
            scanRecursively: true,
            clamscan: {
                path: 'C:\\Program Files\\ClamWin\\bin\\clamscan.exe', // Adjust to your ClamAV path
                scanArchives: true,
                active: true
            },
            clamdscan: {
                socket: false,
                host: 'localhost',
                port: 3310,
                active: false
            }
        });
        console.log('✅ ClamAV iniciado com sucesso!');
    } catch (err) {
        console.warn('⚠️ ClamAV não disponível. Continuando sem scanner de vírus:', err.message);
        // Fallback: Allow uploads without scanning
        clamscan = null;
    }
})();

// Middleware de autenticação
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token de acesso requerido' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'codeshare_secret_key', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido' });
        }
        req.user = user;
        next();
    });
};

// Middleware de moderação
const checkBanned = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.userId);
        if (user.isBanned) {
            return res.status(403).json({ error: 'Usuário banido' });
        }
        next();
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
};

// Função de sanitização
const sanitizeInput = (input) => {
    return validator.escape(xss(input.trim()));
};

// Função de hash de arquivo
const crypto = require('crypto');
const getFileHash = (filePath) => {
    const fileBuffer = fs.readFileSync(filePath);
    const hashSum = crypto.createHash('sha256');
    hashSum.update(fileBuffer);
    return hashSum.digest('hex');
};

// ROTAS DA API

// Registro de usuário
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Validação
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Todos os campos são obrigatórios' });
        }

        if (!validator.isEmail(email)) {
            return res.status(400).json({ error: 'Email inválido' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Senha deve ter pelo menos 6 caracteres' });
        }

        // Verificar se usuário já existe
        const existingUser = await User.findOne({
            $or: [{ email }, { username }]
        });

        if (existingUser) {
            return res.status(400).json({ error: 'Usuário ou email já existe' });
        }

        // Hash da senha
        const hashedPassword = await bcrypt.hash(password, 12);

        // Criar usuário
        const user = new User({
            username: sanitizeInput(username),
            email: email.toLowerCase(),
            password: hashedPassword
        });

        await user.save();

        // Gerar token
        const token = jwt.sign(
            { userId: user._id, username: user.username },
            process.env.JWT_SECRET || 'codeshare_secret_key',
            { expiresIn: '7d' }
        );

        res.status(201).json({
            message: 'Usuário criado com sucesso',
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                reputation: user.reputation
            }
        });
    } catch (error) {
        console.error('Erro no registro:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email e senha são obrigatórios' });
        }

        // Buscar usuário
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        if (user.isBanned) {
            return res.status(403).json({ error: 'Usuário banido' });
        }

        // Verificar senha
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        // Atualizar última atividade
        user.lastActive = new Date();
        await user.save();

        // Gerar token
        const token = jwt.sign(
            { userId: user._id, username: user.username },
            process.env.JWT_SECRET || 'codeshare_secret_key',
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Login realizado com sucesso',
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                reputation: user.reputation,
                isAdmin: user.isAdmin
            }
        });
    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Upload de software
app.post('/api/software/upload', uploadLimiter, authenticateToken, checkBanned, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'Nenhum arquivo foi enviado' });
        }

        const { title, description, category, tags, license } = req.body;

        // Validação
        if (!title || !description || !category || !license) {
            // Remover arquivo se validação falhar
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ error: 'Todos os campos obrigatórios devem be preenchidos' });
        }

        // Gerar hash do arquivo
        const fileHash = getFileHash(req.file.path);

        // Verificar se arquivo já existe
        const existingFile = await Software.findOne({ hash: fileHash });
        if (existingFile) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ error: 'Este arquivo já foi enviado anteriormente' });
        }

        // Scan de vírus
        let virusScanResult = {
            scanned: false,
            clean: true, // Fallback: assume clean if no ClamAV
            scanDate: new Date(),
            threats: []
        };

        if (clamscan) {
            try {
                const scanResult = await clamscan.scanFile(req.file.path);
                virusScanResult = {
                    scanned: true,
                    clean: scanResult.isInfected === false,
                    scanDate: new Date(),
                    threats: scanResult.viruses || []
                };

                if (scanResult.isInfected) {
                    fs.unlinkSync(req.file.path);
                    return res.status(400).json({ 
                        error: 'Arquivo infectado detectado',
                        threats: scanResult.viruses
                    });
                }
            } catch (scanError) {
                console.warn('Erro no scan de vírus:', scanError);
            }
        }

        // Processar tags
        const processedTags = tags ? 
            tags.split(',').map(tag => sanitizeInput(tag)).filter(tag => tag.length > 0) : 
            [];

        // Criar registro do software
        const software = new Software({
            title: sanitizeInput(title),
            description: sanitizeInput(description),
            category,
            tags: processedTags,
            license,
            filename: req.file.filename,
            originalName: req.file.originalname,
            fileSize: req.file.size,
            fileType: path.extname(req.file.originalname).toLowerCase(),
            filePath: req.file.path,
            hash: fileHash,
            virusScanResult,
            uploader: req.user.userId,
            isApproved: virusScanResult.clean // Auto-aprovar se passou no scan ou sem ClamAV
        });

        await software.save();

        // Atualizar contador de uploads do usuário
        await User.findByIdAndUpdate(req.user.userId, { 
            $inc: { uploadCount: 1, reputation: 5 } 
        });

        res.status(201).json({
            message: 'Software enviado com sucesso',
            software: {
                id: software._id,
                title: software.title,
                category: software.category,
                isApproved: software.isApproved,
                virusScanResult: software.virusScanResult
            }
        });

    } catch (error) {
        // Remover arquivo em caso de erro
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        console.error('Erro no upload:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Listar software
app.get('/api/software', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 12;
        const category = req.query.category;
        const search = req.query.search;
        const sort = req.query.sort || 'createdAt';

        let query = { isApproved: true };

        if (category && category !== 'all') {
            query.category = category;
        }

        if (search) {
            query.$or = [
                { title: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } },
                { tags: { $in: [new RegExp(search, 'i')] } }
            ];
        }

        const sortOptions = {};
        switch (sort) {
            case 'downloads':
                sortOptions.downloads = -1;
                break;
            case 'rating':
                sortOptions.rating = -1;
                break;
            case 'newest':
                sortOptions.createdAt = -1;
                break;
            default:
                sortOptions.createdAt = -1;
        }

        const software = await Software.find(query)
            .populate('uploader', 'username reputation')
            .sort(sortOptions)
            .skip((page - 1) * limit)
            .limit(limit);

        const total = await Software.countDocuments(query);

        res.json({
            software,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit)
            }
        });

    } catch (error) {
        console.error('Erro ao listar software:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Download de software
app.get('/api/software/:id/download', authenticateToken, async (req, res) => {
    try {
        const software = await Software.findById(req.params.id);
        
        if (!software || !software.isApproved) {
            return res.status(404).json({ error: 'Software não encontrado' });
        }

        if (!fs.existsSync(software.filePath)) {
            return res.status(404).json({ error: 'Arquivo não disponível' });
        }

        // Incrementar contador de downloads
        await Software.findByIdAndUpdate(req.params.id, { 
            $inc: { downloads: 1 } 
        });

        // Incrementar contador do usuário
        await User.findByIdAndUpdate(req.user.userId, { 
            $inc: { downloadCount: 1 } 
        });

        res.download(software.filePath, software.originalName);

    } catch (error) {
        console.error('Erro no download:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Avaliar software
app.post('/api/software/:id/review', authenticateToken, checkBanned, async (req, res) => {
    try {
        const { rating, comment } = req.body;
        const softwareId = req.params.id;

        if (!rating || rating < 1 || rating > 5) {
            return res.status(400).json({ error: 'Avaliação deve ser entre 1 e 5 estrelas' });
        }

        // Verificar se usuário já avaliou
        const existingReview = await Review.findOne({
            software: softwareId,
            user: req.user.userId
        });

        if (existingReview) {
            return res.status(400).json({ error: 'Você já avaliou este software' });
        }

        // Criar avaliação
        const review = new Review({
            software: softwareId,
            user: req.user.userId,
            rating,
            comment: comment ? sanitizeInput(comment) : ''
        });

        await review.save();

        // Atualizar média de avaliação do software
        const reviews = await Review.find({ software: softwareId });
        const avgRating = reviews.reduce((sum, r) => sum + r.rating, 0) / reviews.length;

        await Software.findByIdAndUpdate(softwareId, {
            rating: Math.round(avgRating * 10) / 10,
            ratingCount: reviews.length
        });

        res.status(201).json({
            message: 'Avaliação enviada com sucesso',
            review: {
                id: review._id,
                rating: review.rating,
                comment: review.comment,
                createdAt: review.createdAt
            }
        });

    } catch (error) {
        console.error('Erro ao avaliar:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Reportar conteúdo
app.post('/api/report', authenticateToken, async (req, res) => {
    try {
        const { targetId, targetType, reason, description } = req.body;

        if (!targetId || !targetType || !reason) {
            return res.status(400).json({ error: 'Dados obrigatórios em falta' });
        }

        const report = new Report({
            reporter: req.user.userId,
            target: targetId,
            targetType,
            reason,
            description: description ? sanitizeInput(description) : ''
        });

        await report.save();

        // Incrementar contador de reports no alvo
        const updateField = { $inc: { reportCount: 1, isReported: true } };
        
        switch (targetType) {
            case 'software':
                await Software.findByIdAndUpdate(targetId, updateField);
                break;
            case 'review':
                await Review.findByIdAndUpdate(targetId, updateField);
                break;
            case 'message':
                await ChatMessage.findByIdAndUpdate(targetId, updateField);
                break;
        }

        res.status(201).json({ message: 'Report enviado com sucesso' });

    } catch (error) {
        console.error('Erro ao reportar:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Estatísticas
app.get('/api/stats', async (req, res) => {
    try {
        const [
            totalSoftware,
            totalUsers,
            totalDownloads,
            todayUploads
        ] = await Promise.all([
            Software.countDocuments({ isApproved: true }),
            User.countDocuments(),
            Software.aggregate([{ $group: { _id: null, total: { $sum: '$downloads' } } }]),
            Software.countDocuments({
                isApproved: true,
                createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
            })
        ]);

        const stats = {
            pcSoftware: await Software.countDocuments({ 
                isApproved: true, 
                category: { $regex: /^pc-/ } 
            }),
            androidApps: await Software.countDocuments({ 
                isApproved: true, 
                category: { $regex: /^android-/ } 
            }),
            scripts: await Software.countDocuments({ 
                isApproved: true, 
                category: { $regex: /^script-/ } 
            }),
            todayDownloads: totalDownloads[0]?.total || 0
        };

        res.json(stats);

    } catch (error) {
        console.error('Erro ao buscar estatísticas:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

module.exports = { app, server, io, User, Software, Review, ChatMessage, Report, authenticateToken, checkBanned, sanitizeInput };