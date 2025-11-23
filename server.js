require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const FormData = require('form-data');
const axios = require('axios');
const { Readable } = require('stream');
const fs = require('fs');
const archiver = require('archiver');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const { body, validationResult, param } = require('express-validator');


const app = express();
const port = 3001;

// Trust the first proxy (e.g., Render's load balancer)
// This is crucial for express-rate-limit to work correctly behind a proxy.
app.set('trust proxy', 1);

console.log("Starting WormX Drive backend...");

// --- Security Middleware ---
app.use(helmet());

// Allow all cross-origin requests. This is simpler for development and for use in
// environments like online IDEs where the frontend origin might be dynamic.
app.use(cors());
console.log("Security middleware (Helmet, CORS) configured.");

const authLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 10, // Limit each IP to 10 requests per windowMs
	standardHeaders: true, 
	legacyHeaders: false, 
  message: 'Too many requests from this IP, please try again after 15 minutes',
});
console.log("Rate limiting configured for authentication routes.");

app.use(express.json());
app.use(mongoSanitize()); // Sanitize input to prevent NoSQL injection

const TELEGRAM_MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024; // 50 MB

const upload = multer({ 
    storage: multer.diskStorage({}), // use OS default temp dir for large files
    limits: { fileSize: TELEGRAM_MAX_FILE_SIZE_BYTES } // Telegram Bot API has a 50MB limit for this upload method.
});
console.log("Middleware (express.json, multer, mongo-sanitize) configured.");

// --- Environment Variable Validation ---
const { DB_URI, CHAT_ID, BOT_TOKEN, JWT_SECRET } = process.env;
const requiredEnvVars = { DB_URI, CHAT_ID, BOT_TOKEN, JWT_SECRET };
for (const [key, value] of Object.entries(requiredEnvVars)) {
    if (!value) {
        console.error("---------------------------------------------------------------");
        console.error(`FATAL ERROR: Environment variable ${key} is not defined.`);
        console.error("Please create a '.env' file in the 'backend' directory by");
        console.error("copying '.env.example' and filling in the required values.");
        console.error("---------------------------------------------------------------");
        process.exit(1);
    }
}

// --- MongoDB Connection ---
console.log("Attempting to connect to MongoDB...");
mongoose.connect(DB_URI)
  .then(() => {
    console.log("✅ Successfully connected to MongoDB.");
  })
  .catch(err => {
    console.error("---------------------------------------------------------------");
    console.error("❌ MongoDB connection error. Please ensure MongoDB is running");
    console.error("and the DB_URI in your .env file is correct.");
    console.error("Error details:", err.message);
    console.error("---------------------------------------------------------------");
    process.exit(1);
  });

// --- Mongoose Schemas ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, index: true, trim: true },
    email: { type: String, required: true, unique: true, index: true, lowercase: true, trim: true },
    phone: { type: String, required: true, unique: true, index: true, trim: true },
    password: { type: String, required: true }
  },
  { timestamps: true }
);

UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

UserSchema.methods.comparePassword = function (plain) {
  return bcrypt.compare(plain, this.password);
};

const StoredFileSchema = new mongoose.Schema({
  // Telegram-specific fields
  fileId: { type: String, unique: true, sparse: true, index: true },
  fileUniqueId: { type: String, unique: true, sparse: true, index: true },

  // Metadata and hierarchy
  fileName: { type: String, required: true },
  mimeType: { type: String, required: true },
  fileSize: { type: Number, default: null },
  parentId: { type: String, required: true, default: 'root', index: true },
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },

  // App-specific flags
  trashed: { type: Boolean, default: false, index: true },
  trashedAt: { type: Date, default: null },
  isFavorite: { type: Boolean, default: false },
  isQuickAccess: { type: Boolean, default: false },
}, { timestamps: true });

const User = mongoose.model("User", UserSchema);
const StoredFile = mongoose.model("StoredFile", StoredFileSchema);


// --- Authentication Middleware ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user; // user payload is { id: user._id }
        next();
    });
};

// --- Validation Middleware ---
const validate = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ message: "Validation failed.", errors: errors.array() });
    }
    next();
};

// --- API ENDPOINTS ---

// --- Validation Rules ---
const isValidParentId = (value) => {
    if (value === 'root' || mongoose.Types.ObjectId.isValid(value)) {
        return true;
    }
    throw new Error('Invalid parent ID format.');
};

const registerValidation = [
    body('email').isEmail().withMessage('Please enter a valid email address.').normalizeEmail(),
    body('username').isLength({ min: 3 }).withMessage('Username must be at least 3 characters long.').trim().escape(),
    body('password').isStrongPassword({
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1,
    }).withMessage('Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a number, and a special character.'),
    body('phone').isMobilePhone('any').withMessage('Please enter a valid phone number.')
];
const loginValidation = [
    body('email').isEmail().withMessage('Please enter a valid email.').normalizeEmail(),
    body('password').notEmpty().withMessage('Password is required.')
];
const createFolderValidation = [
    body('folderName').notEmpty().withMessage('Folder name is required.')
      .isLength({ max: 100 }).withMessage('Folder name cannot exceed 100 characters.')
      .matches(/^[^\\/:"*?<>|]+$/).withMessage('Folder name contains invalid characters.')
      .trim(),
    body('parentId').custom(isValidParentId)
];
const fileIdsValidation = [
    body('fileIds').isArray({ min: 1 }).withMessage('fileIds must be a non-empty array.'),
    body('fileIds.*').isMongoId().withMessage('Each file ID must be a valid Mongo ID.')
];
const moveFilesValidation = [
    ...fileIdsValidation,
    body('destinationParentId').custom(isValidParentId).withMessage('Invalid destination folder.')
];
const mongoIdParamValidation = (paramName) => [
    param(paramName).isMongoId().withMessage(`Invalid ${paramName} format.`)
];


// --- Auth Routes ---
app.post('/api/auth/register', authLimiter, registerValidation, validate, async (req, res) => {
    try {
        const { username, email, phone, password } = req.body;
        
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(409).json({ message: 'User with this email or username already exists.' });
        }

        const user = new User({ username, email, phone, password });
        await user.save();
        res.status(201).json({ message: 'User registered successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error during registration.', error: error.message });
    }
});

app.post('/api/auth/login', authLimiter, loginValidation, validate, async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email }).select('+password');

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const payload = { id: user._id };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' });
        
        const userObj = user.toObject();
        delete userObj.password;

        res.json({ token, user: userObj });
    } catch (error) {
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// Health check
app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

// Get files in a folder
app.get('/api/files/:parentId?', authenticateToken, [param('parentId').optional().custom(isValidParentId)], validate, async (req, res) => {
    try {
        const ownerId = new mongoose.Types.ObjectId(req.user.id);
        const { parentId } = req.params;
        const files = await StoredFile.find({
            ownerId,
            parentId: parentId || 'root',
            trashed: false
        });
        res.json(files.map(f => f.toObject()));
    } catch (error) {
        res.status(500).json({ message: "Failed to fetch files." });
    }
});

// Middleware to handle multer errors
const handleUploadMiddleware = (req, res, next) => {
    const uploadHandler = upload.single('file');
    uploadHandler(req, res, function (err) {
        if (err instanceof multer.MulterError) {
            if (err.code === 'LIMIT_FILE_SIZE') {
                return res.status(413).json({ message: 'File is too large. The maximum upload size is 50 MB.' });
            }
            return res.status(400).json({ message: `File upload error: ${err.message}` });
        } else if (err) {
            return res.status(500).json({ message: `An unknown error occurred during upload.` });
        }
        next();
    });
};

// Upload a file
app.post('/api/files/upload/:parentId', authenticateToken, [param('parentId').custom(isValidParentId)], validate, handleUploadMiddleware, async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded.' });
    }

    try {
        const ownerId = new mongoose.Types.ObjectId(req.user.id);
        const { parentId } = req.params;
        const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendDocument`;
        
        const form = new FormData();
        form.append('chat_id', CHAT_ID);
        form.append('document', fs.createReadStream(req.file.path), req.file.originalname);

        const response = await axios.post(url, form, { 
            headers: form.getHeaders(),
            maxContentLength: Infinity,
            maxBodyLength: Infinity,
        });

        if (!response.data || !response.data.ok || !response.data.result || !response.data.result.document) {
            console.error("Telegram sendDocument unexpected response:", response.data);
            throw new Error('Telegram API did not return expected document data.');
        }

        const tgFile = response.data.result.document;

        const newFile = new StoredFile({
            ownerId,
            parentId,
            fileName: tgFile.file_name,
            mimeType: tgFile.mime_type,
            fileSize: tgFile.file_size,
            fileId: tgFile.file_id,
            fileUniqueId: tgFile.file_unique_id,
        });

        await newFile.save();
        res.status(201).json(newFile.toObject());
    } catch (error) {
        console.error("Detailed upload error:", error); // Log the full error object
        console.error("Upload error:", error.response ? error.response.data : error.message);
        res.status(500).json({ message: 'File upload failed. The file may be too large or the format is not supported.' });
    } finally {
        if (req.file && req.file.path) {
            fs.unlink(req.file.path, (err) => {
                if (err) {
                    console.error("Error deleting temporary upload file:", req.file.path, err);
                }
            });
        }
    }
});

// Download a file
app.get('/api/files/download/:id', authenticateToken, mongoIdParamValidation('id'), validate, async (req, res) => {
    try {
        const ownerId = new mongoose.Types.ObjectId(req.user.id);
        const fileDoc = await StoredFile.findOne({ _id: req.params.id, ownerId });
        if (!fileDoc || !fileDoc.fileId) {
            return res.status(404).json({ message: 'File not found or is a folder.' });
        }

        const fileInfoUrl = `https://api.telegram.org/bot${BOT_TOKEN}/getFile?file_id=${fileDoc.fileId}`;
        const fileInfo = await axios.get(fileInfoUrl);
        const filePath = fileInfo.data.result.file_path;

        const fileUrl = `https://api.telegram.org/file/bot${BOT_TOKEN}/${filePath}`;
        const fileResponse = await axios.get(fileUrl, { responseType: 'stream' });
        
        res.setHeader('Content-Disposition', `attachment; filename="${fileDoc.fileName}"`);
        res.setHeader('Content-Type', fileDoc.mimeType);
        res.setHeader('Content-Length', fileDoc.fileSize);

        fileResponse.data.pipe(res);
    } catch (error) {
        console.error("Download error:", error.response ? error.response.data : error.message);
        res.status(500).json({ message: 'Failed to download file.' });
    }
});

// Create a folder
app.post('/api/folders', authenticateToken, createFolderValidation, validate, async (req, res) => {
    try {
        const ownerId = new mongoose.Types.ObjectId(req.user.id);
        const { folderName, parentId } = req.body;
        const newFolder = new StoredFile({
            ownerId,
            parentId,
            fileName: folderName,
            mimeType: 'application/vnd.wormx-cloud.folder',
            fileSize: null
        });
        await newFolder.save();
        res.status(201).json(newFolder.toObject());
    } catch (error) {
        res.status(500).json({ message: 'Folder creation failed.' });
    }
});

// --- Bulk Operations ---
app.put('/api/files/trash', authenticateToken, fileIdsValidation, validate, async (req, res) => {
    try {
        const ownerId = new mongoose.Types.ObjectId(req.user.id);
        await StoredFile.updateMany({ _id: { $in: req.body.fileIds }, ownerId }, { $set: { trashed: true, trashedAt: new Date() } });
        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ message: 'Failed to trash files.' });
    }
});

app.put('/api/files/restore', authenticateToken, fileIdsValidation, validate, async (req, res) => {
    try {
        const ownerId = new mongoose.Types.ObjectId(req.user.id);
        await StoredFile.updateMany({ _id: { $in: req.body.fileIds }, ownerId }, { $set: { trashed: false, trashedAt: null } });
        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ message: 'Failed to restore files.' });
    }
});

app.delete('/api/files/permanent', authenticateToken, fileIdsValidation, validate, async (req, res) => {
    try {
        const ownerId = new mongoose.Types.ObjectId(req.user.id);
        await StoredFile.deleteMany({ _id: { $in: req.body.fileIds }, ownerId });
        res.status(204).send();
    } catch (error) {
        res.status(500).json({ message: 'Failed to delete files.' });
    }
});

app.put('/api/files/move', authenticateToken, moveFilesValidation, validate, async (req, res) => {
    try {
        const ownerId = new mongoose.Types.ObjectId(req.user.id);
        const { fileIds, destinationParentId } = req.body;
        await StoredFile.updateMany({ _id: { $in: fileIds }, ownerId }, { $set: { parentId: destinationParentId } });
        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ message: 'Failed to move files.' });
    }
});

// --- Trash View ---
app.get('/api/trash', authenticateToken, async (req, res) => {
    try {
        const ownerId = new mongoose.Types.ObjectId(req.user.id);
        const files = await StoredFile.find({ ownerId, trashed: true });
        res.json(files.map(f => f.toObject()));
    } catch (error) {
        res.status(500).json({ message: 'Failed to get trashed files.' });
    }
});

app.delete('/api/trash', authenticateToken, async (req, res) => {
    try {
        const ownerId = new mongoose.Types.ObjectId(req.user.id);
        await StoredFile.deleteMany({ ownerId, trashed: true });
        res.status(204).send();
    } catch (error) {
        res.status(500).json({ message: 'Failed to empty trash.' });
    }
});

// --- Favorites and Quick Access ---
const toggleFlag = (flag) => async (req, res) => {
    try {
        const ownerId = new mongoose.Types.ObjectId(req.user.id);
        const file = await StoredFile.findOne({ _id: req.params.id, ownerId });
        if (!file) return res.status(404).json({ message: 'File not found.' });
        file[flag] = !file[flag];
        await file.save();
        res.json({ success: true, [flag]: file[flag] });
    } catch (error) {
        res.status(500).json({ message: `Failed to toggle ${flag} status.` });
    }
};

app.put('/api/files/favorite/:id', authenticateToken, mongoIdParamValidation('id'), validate, toggleFlag('isFavorite'));
app.put('/api/files/quickaccess/:id', authenticateToken, mongoIdParamValidation('id'), validate, toggleFlag('isQuickAccess'));

app.get('/api/files/favorites', authenticateToken, async (req, res) => {
    try {
        const ownerId = new mongoose.Types.ObjectId(req.user.id);
        const files = await StoredFile.find({ ownerId, isFavorite: true, trashed: false });
        res.json(files.map(f => f.toObject()));
    } catch (error) {
        res.status(500).json({ message: 'Failed to get favorite files.' });
    }
});

app.get('/api/files/quickaccess', authenticateToken, async (req, res) => {
    try {
        const ownerId = new mongoose.Types.ObjectId(req.user.id);
        const files = await StoredFile.find({ ownerId, isQuickAccess: true, trashed: false });
        res.json(files.map(f => f.toObject()));
    } catch (error) {
        res.status(500).json({ message: 'Failed to get quick access files.' });
    }
});

// --- Search ---
const buildPathForFile = async (fileId) => {
    const path = [];
    const visitedIds = new Set();
    let currentFile = await StoredFile.findById(fileId).lean();
    
    while (currentFile) {
        if (visitedIds.has(currentFile._id.toString())) break;
        visitedIds.add(currentFile._id.toString());
        path.unshift({ id: currentFile._id.toString(), name: currentFile.fileName });
        if (currentFile.parentId === 'root' || !currentFile.parentId) break;
        currentFile = await StoredFile.findById(currentFile.parentId).lean();
    }
    path.unshift({ id: 'root', name: 'Drive' });
    return path;
};

app.get('/api/search', authenticateToken, async (req, res) => {
    try {
        const ownerId = new mongoose.Types.ObjectId(req.user.id);
        const { query, type, dateRange, sizeRange } = req.query;
        if (!query) return res.json([]);

        const filter = {
            ownerId,
            trashed: false,
            fileName: { $regex: query, $options: 'i' }
        };
        
        // File Type Filter
        if (type) {
            switch (type) {
                case 'image': filter.mimeType = /^image\//i; break;
                case 'video': filter.mimeType = /^video\//i; break;
                case 'document': filter.mimeType = /pdf|document|text|spreadsheet/i; break;
                case 'folder': filter.mimeType = 'application/vnd.wormx-cloud.folder'; break;
            }
        }
        
        // Date Modified Filter
        if (dateRange) {
            const now = new Date();
            let startDate;
            switch (dateRange) {
                case 'day': startDate = new Date(now.setDate(now.getDate() - 1)); break;
                case 'week': startDate = new Date(now.setDate(now.getDate() - 7)); break;
                case 'month': startDate = new Date(now.setMonth(now.getMonth() - 1)); break;
                case 'year': startDate = new Date(now.setFullYear(now.getFullYear() - 1)); break;
            }
            if (startDate) {
                filter.updatedAt = { $gte: startDate };
            }
        }

        // File Size Filter
        if (sizeRange) {
            const MB = 1024 * 1024;
            let sizeFilter = null;
            switch (sizeRange) {
                case 'small': sizeFilter = { $lt: MB }; break; // < 1MB
                case 'medium': sizeFilter = { $gte: MB, $lte: 100 * MB }; break; // 1-100MB
                case 'large': sizeFilter = { $gte: 100 * MB, $lte: 1024 * MB }; break; // 100MB - 1GB
                case 'xlarge': sizeFilter = { $gte: 1024 * MB }; break; // > 1GB
            }
            if (sizeFilter) {
                filter.fileSize = sizeFilter;
            }
        }

        const results = await StoredFile.find(filter).lean();

        const resultsWithPath = await Promise.all(
            results.map(async file => ({ ...file, path: await buildPathForFile(file._id) }))
        );
        res.json(resultsWithPath);
    } catch (error) {
        res.status(500).json({ message: 'Search failed.' });
    }
});

// --- Stats ---
app.get('/api/stats/storage', authenticateToken, async (req, res) => {
    const ownerId = new mongoose.Types.ObjectId(req.user.id);
    const result = await StoredFile.aggregate([
        { $match: { ownerId, trashed: false, fileSize: { $ne: null } } },
        { $group: { _id: null, totalSize: { $sum: '$fileSize' } } }
    ]);
    res.json({ totalSize: result[0]?.totalSize || 0 });
});

app.get('/api/stats/categories', authenticateToken, async (req, res) => {
    const ownerId = new mongoose.Types.ObjectId(req.user.id);
    const results = await StoredFile.aggregate([
      { $match: { ownerId, trashed: false, fileSize: { $ne: null } } },
      { $project: {
          category: { $switch: {
              branches: [
                  { case: { $regexMatch: { input: '$mimeType', regex: '^image/' } }, then: 'image' },
                  { case: { $regexMatch: { input: '$mimeType', regex: '^video/' } }, then: 'video' },
                  { case: { $in: ['$mimeType', ['application/pdf', 'text/plain']] }, then: 'document' },
                  { case: { $regexMatch: { input: '$mimeType', regex: 'document|spreadsheet' } }, then: 'document' }
              ],
              default: 'others'
          }},
          fileSize: 1
      }},
      { $group: {
          _id: '$category',
          totalSize: { $sum: '$fileSize' },
          count: { $sum: 1 }
      }}
    ]);
    const stats = results.reduce((acc, item) => {
        acc[item._id] = { totalSize: item.totalSize, count: item.count };
        return acc;
    }, {});
    res.json(stats);
});

app.get('/api/stats/trash', authenticateToken, async (req, res) => {
    const ownerId = new mongoose.Types.ObjectId(req.user.id);
    const result = await StoredFile.aggregate([
        { $match: { ownerId, trashed: true, fileSize: { $ne: null } } },
        { $group: { _id: null, totalSize: { $sum: '$fileSize' }, count: { $sum: 1 } } }
    ]);
    res.json({ totalSize: result[0]?.totalSize || 0, count: result[0]?.count || 0 });
});

// --- Folder Download (ZIP) ---
const getAllFilesRecursive = async (ownerId, folderId) => {
    let files = [];
    const items = await StoredFile.find({ ownerId, parentId: folderId, trashed: false }).lean();
    for (const item of items) {
        if (item.mimeType === 'application/vnd.wormx-cloud.folder') {
            const subFiles = await getAllFilesRecursive(ownerId, item._id.toString());
            files = files.concat(subFiles.map(sf => ({ ...sf, path: `${item.fileName}/${sf.path}` })));
        } else {
            files.push({ ...item, path: item.fileName });
        }
    }
    return files;
};

app.get('/api/folders/zip/:folderId', authenticateToken, mongoIdParamValidation('folderId'), validate, async (req, res) => {
    try {
        const { folderId } = req.params;
        const ownerId = new mongoose.Types.ObjectId(req.user.id);
        
        const rootFolder = await StoredFile.findOne({ _id: folderId, ownerId }).lean();
        if (!rootFolder) return res.status(404).send('Folder not found or you do not have permission to access it.');

        const filesToZip = await getAllFilesRecursive(ownerId, folderId);
        
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename=${rootFolder.fileName}.zip`);

        const archive = archiver('zip', { zlib: { level: 9 } });
        archive.pipe(res);

        for (const file of filesToZip) {
            if (!file.fileId) continue; // Skip if it's a folder structure entry without a fileId
            const fileInfoUrl = `https://api.telegram.org/bot${BOT_TOKEN}/getFile?file_id=${file.fileId}`;
            const fileInfo = await axios.get(fileInfoUrl);
            const filePath = fileInfo.data.result.file_path;
            const fileUrl = `https://api.telegram.org/file/bot${BOT_TOKEN}/${filePath}`;
            const fileStream = (await axios.get(fileUrl, { responseType: 'stream' })).data;
            archive.append(fileStream, { name: file.path });
        }

        archive.finalize();
    } catch (err) {
        console.error('ZIP creation failed:', err);
        res.status(500).send('Failed to create ZIP file');
    }
});

app.listen(port, () => {
    console.log(`✅ WormX Drive backend listening at http://localhost:${port}`);
});
