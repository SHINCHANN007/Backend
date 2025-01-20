// server.js
const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const authRoutes = require('./routes/auth');
const gameRoutes = require('./routes/game');
const friendRequestRoutes = require('./routes/friendRequestRoutes');
const cors = require('cors');
const credentials = require('./middleware/credentials');
const corsOptions = require('./config/corsOptions');


dotenv.config();

const verifyToken = require('./middleware/authMiddleware');

const app = express();

//path to store photo
const fs = require('fs');
const path = require('path');


// Middleware
app.use(credentials); // Apply credentials middleware
app.use(cors(corsOptions)); // Apply CORS with specified options
app.use(express.json()); // Middleware to parse JSON request bodies

app.use(express.json());
// Routes
app.use('/api/auth', authRoutes); // Auth routes (e.g., login, register)
app.use('/api/game',  gameRoutes); // Game routes with token verification
app.use('/api/friend-requests', friendRequestRoutes);

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch((error) => console.error('MongoDB connection error:', error));

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
