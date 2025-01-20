// models/FriendRequest.js
const mongoose = require('mongoose');

const friendRequestSchema = new mongoose.Schema({
  senderUsername: {
    type: String,
    required: true,
  },
  receiverUsername: {
    type: String,
    required: true,
  },
  status: {
    type: String,
    enum: ['pending', 'accepted', 'rejected'],
    default: 'pending',
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model('FriendRequest', friendRequestSchema);