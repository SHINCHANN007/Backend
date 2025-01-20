// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true, // Ensures email is stored in lowercase
  },
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
  },
  friends:{
    type: Array,
    default: [],
  },
  coverImage: {
    type: String,
    default: '', // Default to an empty string if no image is provided
  },
  profileImage: {
    type: String,
    default: '', // Default to an empty string if no image is provided
  },
  birthday: {
    type: String, // Store birthday as a string in format DD-MMM-YYYY or another format as needed
    required: true,
  },
  resetPasswordToken: {
    type: String, // Store birthday as a string in format DD-MMM-YYYY or another format as needed
    default:"",
  },
}, {
  timestamps: true, // Automatically add createdAt and updatedAt fields
});

module.exports = mongoose.model('User', userSchema);

