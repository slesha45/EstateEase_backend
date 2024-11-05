const Wishlist = require('../models/wishlistModels');
const Property = require('../models/propertyModels')

const getUserWishlist = async (req, res) => {
  try {
      const wishlist = await Wishlist.findOne({ user: req.user._id }).populate('properties');
      if (!wishlist) {
        return res.status(200).json({
            success: true,
            data: []
        });
    }

    res.status(200).json({
        success: true,
        data: wishlist.properties 
    });
} catch (error) {
    console.error('Error fetching user wishlist:', error); 
    res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error.message
    });
}
};

// Add to wishlist
const addToWishlist = async (req, res) => {
  try {
      const { propertyId } = req.body;
      console.log('Request Body:', req.body);
      const property = await Property.findById(propertyId);
      if (!property) {
          return res.status(404).json({
              success: false,
              message: 'Property not found'
          });
      }

      let wishlist = await Wishlist.findOne({ user: req.user._id });
      if (!wishlist) {
          wishlist = new Wishlist({ user: req.user._id, properties: [propertyId] });
      } else {
          if (!wishlist.properties.includes(propertyId)) {
              wishlist.properties.push(propertyId);
          }
      }

      await wishlist.save();
      res.status(200).json({
          success: true,
          message: 'Property added to wishlist',
          data: wishlist
      });
  } catch (error) {
      res.status(500).json({
          success: false,
          message: 'Internal server error',
          error: error.message
      });
  }
};

// Remove from wishlist
const removeFromWishlist = async (req, res) => {
  try {
      const { propertyId } = req.params;
      let wishlist = await Wishlist.findOne({ user: req.user._id });

      if (wishlist) {
          wishlist.properties = wishlist.properties.filter(id => id.toString() !== propertyId);
          await wishlist.save();
      }

      res.status(200).json({
          success: true,
          message: 'Property removed from wishlist',
          data: wishlist
      });
  } catch (error) {
      res.status(500).json({
          success: false,
          message: 'Internal server error',
          error: error.message
      });
  }
};


module.exports = {
  addToWishlist,
  getUserWishlist,
  removeFromWishlist
};