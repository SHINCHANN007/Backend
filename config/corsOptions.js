// corsOptions.js
const allowedOrigins = require('./allowedOrigins');

const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (e.g., mobile apps or curl requests)
        if (allowedOrigins.includes(origin) || !origin) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // Specify allowed methods
    credentials: true, // Allow credentials if needed (cookies, etc.)
};

module.exports = corsOptions;
