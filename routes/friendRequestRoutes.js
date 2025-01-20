const express = require('express');
const router = express.Router();
const friendRequestController = require('../controllers/friendRequestController');
const verifyToken = require('../middleware/authMiddleware');

// Route to send a friend request
router.post('/send', friendRequestController.sendFriendRequest);

// Route to accept a friend request
router.post('/accept/:senderUsername/:receiverUsername',  friendRequestController.acceptFriendRequest);

// Route to reject a friend request
router.post('/reject/:senderUsername/:receiverUsername',  friendRequestController.rejectFriendRequest);

// Route to get friend requests
router.get('/requests/:username',  friendRequestController.getFriendRequests);

router.get('/show/:username',  friendRequestController.showFriends);

module.exports = router;
