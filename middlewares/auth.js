const { verifyAccessToken } = require('../utils/tokenUtils');

exports.isAuthenticatedWithSession = (req, res, next) => {
    if (req.session && req.session.userId) {
        return next();
    }

    res.status(401).json({
        success: false,
        message: 'Veuillez vous connecter pour accéder à cette ressource'
    });
};

exports.authorizeWithSession = (roles) => {
    return (req, res, next) => {
        if (!req.session || !req.session.userRole) {
            return res.status(401).json({
                success: false,
                message: 'Veuillez vous connecter pour accéder à cette ressource'
            });
        }

        if (!roles.includes(req.session.userRole)) {
            return res.status(403).json({
                success: false,
                message: 'Vous n\'êtes pas autorisé à accéder à cette ressource'
            });
        }

        next();
    };
};

exports.isAuthenticatedWithJWT = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: 'Accès non autorisé. Token manquant ou format incorrect'
            });
        }

        const token = authHeader.split(' ')[1];

        const decoded = verifyAccessToken(token);

        req.user = decoded;

        next();
    } catch (error) {
        res.status(401).json({
            success: false,
            message: 'Accès non autorisé. Token invalide ou expiré',
            error: error.message
        });
    }
};

exports.authorizeWithJWT = (roles) => {
    return (req, res, next) => {
        if (!req.user || !req.user.role) {
            return res.status(401).json({
                success: false,
                message: 'Accès non autorisé. Authentification requise'
            });
        }

        if (!roles.includes(req.user.role)) {
            return res.status(403).json({
                success: false,
                message: 'Accès interdit. Vous n\'avez pas les droits nécessaires'
            });
        }

        next();
    };
};
