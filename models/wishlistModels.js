const mongoose = require("mongoose");

const wishlistSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'users',
    required: true
  },
  properties: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'properties',
    required: true
  }],
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const Wishlist = mongoose.model("wishlists", wishlistSchema);
module.exports = Wishlist;