// models/Game.js
const mongoose = require('mongoose');

const gameSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
  },
  gameName: {
    type: String,
    required: true,
  },
  score: {
    type: Number,
    required: true,
    default:0,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model('Game', gameSchema);
