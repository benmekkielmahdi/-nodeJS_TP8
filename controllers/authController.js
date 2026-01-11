const User = require('../models/User');
const {
    generateAccessToken,
    generateRefreshToken,
    verifyRefreshToken
} = require('../utils/tokenUtils');

// Session Auth
exports.registerWithSession = async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const existingUser = await User.findOne({
            $or: [{ email }, { username }]
        });

        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'Cet email ou nom d\'utilisateur est déjà utilisé'
            });
        }

        const user = await User.create({ username, email, password });
        user.password = undefined;

        req.session.userId = user._id;
        req.session.userRole = user.role;

        res.status(201).json({ success: true, message: 'Inscription réussie', data: user });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erreur lors de l\'inscription', error: error.message });
    }
};

exports.loginWithSession = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email }).select('+password');

        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).json({ success: false, message: 'Email ou mot de passe incorrect' });
        }

        req.session.userId = user._id;
        req.session.userRole = user.role;
        user.password = undefined;

        res.status(200).json({ success: true, message: 'Connexion réussie', data: user });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erreur lors de la connexion', error: error.message });
    }
};

exports.logoutWithSession = (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Erreur lors de la déconnexion', error: err.message });
        }
        res.clearCookie('connect.sid');
        res.status(200).json({ success: true, message: 'Déconnexion réussie' });
    });
};

exports.getProfileWithSession = async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        if (!user) return res.status(404).json({ success: false, message: 'Utilisateur non trouvé' });
        res.status(200).json({ success: true, data: user });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erreur lors de la récupération du profil', error: error.message });
    }
};

// JWT Auth
exports.registerWithJWT = async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });

        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Cet email ou nom d\'utilisateur est déjà utilisé' });
        }

        const user = await User.create({ username, email, password });
        const accessToken = generateAccessToken(user._id, user.role);
        const refreshToken = generateRefreshToken(user._id);

        user.refreshToken = refreshToken;
        await user.save();
        user.password = undefined;
        user.refreshToken = undefined;

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.status(201).json({ success: true, message: 'Inscription réussie', accessToken, data: user });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erreur lors de l\'inscription', error: error.message });
    }
};

exports.loginWithJWT = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email }).select('+password');

        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).json({ success: false, message: 'Email ou mot de passe incorrect' });
        }

        const accessToken = generateAccessToken(user._id, user.role);
        const refreshToken = generateRefreshToken(user._id);

        user.refreshToken = refreshToken;
        await user.save();
        user.password = undefined;
        user.refreshToken = undefined;

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.status(200).json({ success: true, message: 'Connexion réussie', accessToken, data: user });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erreur lors de la connexion', error: error.message });
    }
};

exports.logoutWithJWT = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;

        if (refreshToken) {
            const user = await User.findOne({ refreshToken });
            if (user) {
                user.refreshToken = undefined;
                await user.save();
            }
        }
        res.clearCookie('refreshToken');
        res.status(200).json({ success: true, message: 'Déconnexion réussie' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erreur lors de la déconnexion', error: error.message });
    }
};

exports.refreshToken = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) return res.status(401).json({ success: false, message: 'Refresh token manquant' });

        const decoded = verifyRefreshToken(refreshToken);
        const user = await User.findOne({ _id: decoded.id, refreshToken });

        if (!user) return res.status(401).json({ success: false, message: 'Refresh token invalide' });

        const accessToken = generateAccessToken(user._id, user.role);
        res.status(200).json({ success: true, accessToken });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Refresh token invalide ou expiré', error: error.message });
    }
};

exports.getProfileWithJWT = async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ success: false, message: 'Utilisateur non trouvé' });
        res.status(200).json({ success: true, data: user });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Erreur lors de la récupération du profil', error: error.message });
    }
};
