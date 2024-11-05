// routes/contactRoutes.js
 
const express = require('express');
const router = express.Router();
const contactController = require('../controllers/contactControllers');
 
router.post('/contact', contactController.submitContactForm);
 
router.get('/all', contactController.getAllContacts);
 
module.exports = router;