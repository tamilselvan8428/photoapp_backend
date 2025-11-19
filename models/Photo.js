const mongoose = require('mongoose');
const photoSchema = new mongoose.Schema({
  title: String,
  description: String,
  imageBase64: String,
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Photo', photoSchema);