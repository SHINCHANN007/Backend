// routes/auth.js
const express = require('express');
const { signup, login, userdetails, uploadPhoto, uploadPfp, sendResetToken, checkResetToken, resetPassword } = require('../controllers/authController');

const router = express.Router();

const multer = require('multer');

const path = require('path')
//multer lets u store anywhere file
// Configure multer storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Resolve the uploads directory relative to the current file
    cb(null, path.join(__dirname, '../uploads'));
  },
  filename: function (req, file, cb) {
    // Ensure username is available and sanitize filename
    const username = req.body.username || 'default_user'; // Default value if username is not provided
    //const ext = path.extname(file.originalname);  Get file extension
    cb(null, `${username}_${Date.now()}_${file.originalname}`); // Unique filename
  }
});

const upload = multer({storage});

// Signup Route
router.post('/signup', signup);

// Login Route
router.post('/login', login);

// details taker
router.post('/userdetails', userdetails);

//reset email
router.post('/send-reset-token', sendResetToken);
router.post('/check-reset-token', checkResetToken);
router.post('/reset-password', resetPassword);

// Upload profile photo route (requires token authentication)
router.post('/upload-photo', upload.single('photo') ,uploadPhoto);
router.post('/upload-pfp', upload.single('photop') ,uploadPfp);





module.exports = router;
