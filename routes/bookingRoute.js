const express = require('express');
const router = express.Router();
const bookingController = require('../controllers/bookingControllers');
const { authGuard } = require('../middleware/authGuard');

// Create Booking
router.post('/bookings', authGuard, bookingController.createBooking);

// Get All Bookings (Admin)
router.get('/all_bookings', authGuard, bookingController.getAllBookings);

// Update Booking Status (Admin)
router.put('/bookings/status', authGuard, bookingController.updateBookingStatus);

//Get user booking
router.get('/mybookings', authGuard, bookingController.getUserBookings);

//Update payment method
router.put('/bookings/payment', authGuard, bookingController.updatePaymentMethod);

module.exports = router;
