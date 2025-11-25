const mongoose = require('mongoose');
module.exports = mongoose.model('User', new mongoose.Schema({
  username: { type: String, unique: true },
  credentials: [Object],
  currentChallenge: String
}));
