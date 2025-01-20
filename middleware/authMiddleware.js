const jwt = require('jsonwebtoken');

// Middleware to check if the user is authenticated
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(403).json({ message: 'Access denied. No token provided or token format is incorrect.' });
    }

    const token = authHeader.split(' ')[1]; // Extract token from "Bearer <token>"

    try {
        // Verify the token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Attach the decoded user information to the request object
        
        next();
    } catch (err) {
        console.error('Token verification failed:', err); // Log the error for debugging
        res.status(401).json({ message: 'Invalid token.' });
    }
};

module.exports = verifyToken;
