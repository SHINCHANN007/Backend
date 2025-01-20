// routes/game.js
const express = require('express');
const { addOrUpdateHighScore, getUserHighScore } = require('../controllers/gameController');

const router = express.Router();

// Route to add or update high score
router.post('/high-score', addOrUpdateHighScore);

// Route to get top high scores for a specific game
router.post('/top-scores', getUserHighScore);

module.exports = router;
