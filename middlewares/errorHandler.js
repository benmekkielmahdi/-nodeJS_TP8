const errorHandler = (err, req, res, next) => {
    console.error(err.stack);

    if (err.name === 'ValidationError') {
        const messages = Object.values(err.errors).map(val => val.message);
        return res.status(400).json({
            success: false,
            error: messages.join(', ')
        });
    }

    if (err.code === 11000) {
        return res.status(400).json({
            success: false,
            error: 'Cette valeur existe déjà dans la base de données'
        });
    }

    if (err.name === 'CastError') {
        return res.status(400).json({
            success: false,
            error: 'Identifiant invalide'
        });
    }

    if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({
            success: false,
            error: 'Token invalide'
        });
    }

    if (err.name === 'TokenExpiredError') {
        return res.status(401).json({
            success: false,
            error: 'Token expiré'
        });
    }

    res.status(err.statusCode || 500).json({
        success: false,
        error: process.env.NODE_ENV === 'production'
            ? 'Erreur serveur'
            : err.message
    });
};

module.exports = errorHandler;
