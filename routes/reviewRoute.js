const express = require("express");
const router = express.Router();
const { authGuard } = require("../middleware/authGuard"); // Adjusted path for middleware import
const { addReview, getReviewsByProperty } = require("../controllers/reviewController");
 
// POST route to add a review
router.post("/add", authGuard, addReview); // Added authGuard to ensure user is authenticated
 
// GET route to fetch reviews by artist ID
router.get("/property/:propertyId", getReviewsByProperty);
 
module.exports = router;