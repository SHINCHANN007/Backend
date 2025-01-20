// controllers/friendRequestController.js
const FriendRequest = require('../models/FriendRequest');
const User = require('../models/user');

// Send a friend request
exports.sendFriendRequest = async (req, res) => {
  try {
    const { senderUsername, receiverUsername } = req.body;

    if (senderUsername === receiverUsername) {
      return res.status(400).json({ message: 'You cannot send a friend request to yourself.' });
    }

    // Check if a friend request already exists
    const existingRequest = await FriendRequest.findOne({
      senderUsername,
      receiverUsername,
      status: 'pending',
    });

    if (existingRequest) {
      return res.status(400).json({ message: 'Friend request already sent.' });
    }

    const friendRequest = new FriendRequest({
      senderUsername,
      receiverUsername,
    });

    await friendRequest.save();

    res.status(200).json({ message: 'Friend request sent.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error.', error: err });
  }
};

// Controller for accepting a friend request
exports.acceptFriendRequest = async (req, res) => {
  try {
    const { senderUsername, receiverUsername } = req.params; // Get usernames from URL parameters

    console.log("Received parameters:", { senderUsername, receiverUsername });
    const sender = await User.findOne({username:senderUsername});
    const receiver = await User.findOne({username:receiverUsername});

    // Find the pending friend request by sender and receiver usernames
    const friendRequest = await FriendRequest.findOne({
      senderUsername,
      receiverUsername,
      status: 'pending'
    });

    if (friendRequest) {
      // Update friend request status to 'accepted'
      friendRequest.status = 'accepted';
      await friendRequest.save();
      

        const friendRequesttwo = await FriendRequest.findOne({
          
          senderUsername:receiverUsername,
          receiverUsername:senderUsername,
          status: 'pending'
        });

        if(friendRequesttwo){
          friendRequesttwo.status = 'accepted';
          await friendRequesttwo.save();
        }
        
        sender.friends.push(receiverUsername);
        receiver.friends.push(senderUsername);

        await sender.save();
        await receiver.save();

      res.status(200).json({ message: 'Friend request accepted' });
    } else {
      console.log("Friend request not found with parameters:", { senderUsername, receiverUsername });
      return res.status(400).json({ message: 'Friend request not found.' });
    }
  } catch (err) {
    console.error('Error accepting friend request:', err);
    res.status(500).json({ message: 'Server error.', error: err });
  }
};




// Reject a friend request
exports.rejectFriendRequest = async (req, res) => {
  try {
    const { senderUsername, receiverUsername } = req.params; // Get usernames from URL parameters

    // Find the pending friend request by sender and receiver usernames
    const friendRequest = await FriendRequest.findOne({
      senderUsername,
      receiverUsername,
      status: 'pending'
    });

    if (!friendRequest) {
      return res.status(400).json({ message: 'Invalid or already processed friend request.' });
    }

    // Update friend request status to 'rejected'
    friendRequest.status = 'rejected';
    await friendRequest.save();

    res.status(200).json({ message: 'Friend request rejected.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error.', error: err });
  }
};


// Get friend requests for a user
// Controller function to get friend requests based on username in the URL parameters
exports.getFriendRequests = async (req, res) => {
  try {
    // Get the username from the request parameters
    const { username } = req.params; 

    if (!username) {
      return res.status(400).json({ message: 'Username is required.' });
    }

    // Find the user by username
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    // Find friend requests where the receiver is the user and status is 'pending'
    const friendRequests = await FriendRequest.find({ receiverUsername: username, status: 'pending' })
      .populate('senderUsername', 'receiverUsername'); // Populate senderUsername with the actual username

    // Return the list of friend requests as a response
    res.status(200).json(friendRequests);
  } catch (err) {
    // Return a 500 error if any server error occurs
    res.status(500).json({ message: 'Server error.', error: err });
  }
};

//display friend
exports.showFriends = async (req, res) => {
  try {
    const { username } = req.params; // Get username from URL parameters

    if (!username) {
      return res.status(400).json({ message: 'Username is required.' });
    }

    const flist = await User.findOne({username});
    console.log(flist.friends)

    // Return the list of friends as a response
    res.status(200).json({"friends":flist.friends});
  } catch (err) {
    res.status(500).json({ message: 'Server error.', error: err });
  }
};

