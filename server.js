const express = require('express');
const session = require('express-session');
const redis = require('redis');
const connectDB = require('./config/db');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const errorHandler = require('./middlewares/errorHandler');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3002;

connectDB();

// Initialisation Redis Store (v6)
const RedisStore = require('connect-redis')(session);
const redisClient = redis.createClient({
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
    legacyMode: true // Important for connect-redis v6 compatibility if using redis v4
});

redisClient.connect().catch(console.error); // Needed for redis v4+

redisClient.on('error', (err) => {
    console.log('Erreur Redis:', err);
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Security
app.use(helmet());
// app.use(mongoSanitize()); // Disabled due to compatibility issue with recent Express versions
// app.use(xss()); // Disabled to prevent similar property setting issues

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: {
        success: false,
        message: 'Trop de tentatives de connexion. Veuillez réessayer après 15 minutes'
    }
});

app.use('/api/auth/login-session', loginLimiter);
app.use('/api/auth/login-jwt', loginLimiter);

// Session
app.use(session({
    store: new RedisStore({ client: redisClient }),
    secret: process.env.SESSION_SECRET || 'secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

app.use('/api/auth', require('./routes/authRoutes'));

app.get('/', (req, res) => {
    res.send('API d\'authentification');
});

app.use(errorHandler);

app.listen(PORT, () => {
    console.log(`Serveur en cours d'exécution sur le port ${PORT}`);
});
