const router = require('express').Router();
const proController = require('../controllers/propertyControllers');
const { authGuard } = require("../middleware/authGuard");

//Creating property route
router.post('/create', proController.createProperty)

//Fetch all property
router.get('/get_all_property', authGuard, proController.getAllProperty)

//single property
router.get('/get_single_property/:id', authGuard, proController.getSingleProperty)

//delete property
router.delete('/delete_property/:id', authGuard, proController.deleteProperty)

//update property
router.put('/update_property/:id',authGuard, proController.updateProperty)

//pagination
router.get('/pagination', proController.paginationProperty)

//get property count
router.get('/get_property_count', proController.getPropertyCount)


//Exporting the routes
module.exports = router