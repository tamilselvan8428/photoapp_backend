const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const UserSchema = new mongoose.Schema({
  googleId: { 
    type: String, 
    sparse: true,
    unique: true 
  },
  displayName: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: false,
    select: false
  },
  isVerified: {
    type: Boolean,
    default: false
  }
}, { 
  timestamps: true 
});
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});
UserSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};
const User = mongoose.model('User', UserSchema);
User.collection.dropIndexes(function(err) {
  if (err) {
    console.log('Error dropping indexes:', err);
  } else {
    console.log('Dropped all indexes from users collection');
    User.createIndexes()
      .then(() => console.log('Created indexes'))
      .catch(err => console.error('Error creating indexes:', err));
  }
});
module.exports = User;