// controllers/authController.js
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');


// Signup Controller
// Signup Controller
const signup = async (req, res) => {
  const { email, username, password, birthday } = req.body;

  try {
    // Check if all fields are provided
    if (!email || !username || !password || !birthday) {
      return res.status(400).json({ message: 'All fields are required.' });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'Invalid email format.' });
    }

    // Check if passwords meet basic criteria (e.g., length)
    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters long.' });
    }

    // Check if the username already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'Username already exists.' });
    }

    // Check if the email already exists
    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ message: 'Email already in use.' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user with the validated data
    const user = new User({
      email,
      username,
      password: hashedPassword,
      birthday, // Store birthday as a string or format as needed
    });

    // Save the new user to the database
    await user.save();

    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Login Controller

const login = async (req, res) => {
  const { email, password } = req.body; // Expecting email and password now

  try {
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ token, "username":user.username });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

const userdetails = async (req, res) => {
  const { username } = req.body;

  try {
    if (!username) {
      return res.status(400).json({ message: 'Username is required' });
    }

    // Find user details with projection to only include email and birthday
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ message: 'No user found' });
    }

    // Store email and birthday in variables
    const { email, birthday, profileImage, coverImage } = user;
    console.log(user);

    // Respond with email and birthday
    res.status(200).json({ email, birthday, profileImage, coverImage });
  } catch (error) {
    console.error('Error fetching user details:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Upload Photo Controller

const uploadPhoto = async (req, res) => {
  const username = req.body.username; // Get username from the request body

  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    // Find user by username
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Log current user profile for debugging
    console.log('User before update:', user);

    // Check if user already has a profile image
    if (user.profileImage) {
      // Construct the full path to the old image file
      const oldImagePath = path.join(__dirname, '../uploads', user.profileImage);

      // Delete the old image file
      fs.unlink(oldImagePath, (err) => {
        if (err) {
          console.error('Error deleting old profile image:', err);
          // Optionally, handle the error (e.g., notify the user or continue)
        } else {
          console.log('Old profile image deleted successfully');
        }
      });
    }

    // Store the new file path in the user's profileImage field
    user.profileImage = req.file.filename; // Use filename to store in the database
    await user.save();

    res.status(200).json({ message: 'Profile photo uploaded successfully', photo: req.file.path });
  } catch (error) {
    console.error('Error uploading profile photo:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

const uploadPfp = async (req, res) => {
  const username = req.body.username; // Get username from the request body

  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    // Find user by username
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Log current user profile for debugging
    console.log('User before update:', user);

    // Check if user already has a profile image
    if (user.coverImage) {
      // Construct the full path to the old image file
      const oldImagePath = path.join(__dirname, '../uploads', user.coverImage);

      // Delete the old image file
      fs.unlink(oldImagePath, (err) => {
        if (err) {
          console.error('Error deleting old profile image:', err);
          // Optionally, handle the error (e.g., notify the user or continue)
        } else {
          console.log('Old profile image deleted successfully');
        }
      });
    }

    // Store the new file path in the user's profileImage field
    user.coverImage = req.file.filename; // Use filename to store in the database
    await user.save();

    res.status(200).json({ message: 'Profile photo uploaded successfully', photo: req.file.path });
  } catch (error) {
    console.error('Error uploading profile photo:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

const sendResetToken = async (req, res) => {
  const {email} = req.body;
  const resetToken = crypto.randomBytes(32).toString('hex');

  try{
    const user = await User.findOne({email})
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Save the reset token in the user's record
    user.resetPasswordToken = resetToken;
    console.log(user)
    // Optionally, set an expiry for the token if needed
    // user.resetPasswordTokenExpiry = Date.now() + 3600000; // 1 hour expiry
    await user.save();

    // Set up email transport
    const transporter = nodemailer.createTransport({
      service: 'Gmail', // or another service
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    // Create email
    const mailOptions = {
      to: user.email,
      from: process.env.EMAIL_USER,
      subject: 'Password Reset',
      text: `You are receiving this because you requested to reset your password.
      This is your reset password token: ${resetToken}`,
    };

    // Send the email
    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.error('Error sending email:', err);
        return res.status(500).json({ message: 'Error sending email' });
      }
      res.status(200).json({ message: 'Password reset email sent' });

  })
}
  catch(err){
    console.error(err)  
    res.status(500).json({message:err})
  }
};

const checkResetToken = async(req,res) => {
  try{
  const {resetToken} = req.body;
  const user = await User.findOne({resetPasswordToken:resetToken})
  if(!user){
    return res.status(401).json({ message: 'Invalid reset token' });
    }
    // If the token is valid, return the user's details
    res.status(200).json({ message: 'Reset token is valid', user });
  }
  catch(err){
    console.error('Error checking reset token:', err);
    res.status(500).json({message: err})
  }
}

const resetPassword = async (req,res) => {
  try{
  const {resetToken, newPassword} = req.body;
  const user = await User.findOne({resetPasswordToken:resetToken})
      if (!user) {
        return res.status(401).json({ message: 'Invalid reset token' });
        }
        // Hash the new password
        const hashedPassword = bcrypt.hashSync(newPassword, 10);
        // Update the user's password
        user.password = hashedPassword;
        user.resetPasswordToken = '';
        await user.save()
        res.status(200).json({ message: 'Password reset successfully' });
      }
    
    catch(err){
      console.error('Error resetting password:', err);
      res.status(500).json({message:err})
    }
  }




module.exports = {
  signup,
  login,
  userdetails,
  uploadPhoto,
  uploadPfp,
  resetPassword,
  sendResetToken,
  checkResetToken,
  
};
