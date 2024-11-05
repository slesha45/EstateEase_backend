const Reviews = require("../models/reviewModel");
 
exports.addReview = async (req, res) => {
    const { propertyId, rating, comment } = req.body;
    const userId = req.user._id; // Ensure req.user is populated from authentication middleware
 
    try {
        const review = new Reviews({ propertyId, userId, rating, comment });
        await review.save();
        res.status(201).json({ message: "Review added successfully", review });
    } catch (error) {
        res.status(500).json({ message: "Failed to add review", error });
    }
};
 
exports.getReviewsByProperty = async (req, res) => {
    console.log(req.params.propertyId);
    const propertyId = req.params.propertyId;
 
    try {
        const reviews = await Reviews.find({ propertyId: propertyId })
           
 
        res.status(200).json({ reviews });
    } catch (error) {
        res.status(500).json({ message: "Failed to fetch reviews", error });
    }
};
