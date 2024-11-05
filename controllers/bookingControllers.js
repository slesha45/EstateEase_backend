const Booking = require('../models/bookingModel');
const User = require('../models/userModels');
const Property = require('../models/propertyModels');

// Create Booking
// Backend: bookingControllers.js
const createBooking = async (req, res) => {
  const { userId, propertyId, date, time } = req.body;

  // Validate input
  if (!userId || !propertyId || !date || !time) {
    return res.status(400).json({ success: false, message: 'All fields are required' });
  }

  try {
    // Check if user has a pending or approved booking
    //const existingBooking = await Booking.findOne({ user: userId, status: { $in: ['pending', 'approved'] } });
    // if (existingBooking) {
    //   return res.status(400).json({ success: false, message: 'You already have a pending or approved booking' });
    // }

    // Create new booking
    const newBooking = new Booking({ user: userId, property: propertyId, date, time });
    await newBooking.save();

    res.status(201).json({ success: true, message: 'Booking created successfully', booking: newBooking });
  } catch (error) {
    console.error('Error creating booking:', error.message);  // More detailed error logging
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
};


// Get All Bookings
const getAllBookings = async (req, res) => {
  try {
    let bookings;
    if (req.user.isAdmin) {
      bookings = await Booking.find().populate('user', 'firstName lastName').populate('property', 'propertyTitle');
    } else {
      bookings = await Booking.find({ user: req.user._id }).populate('users', 'firstName lastName').populate('properties', 'propertyTitle')
    }
    return res.status(200).json({ success: true, data: bookings });
  } catch (error) {
    console.error('Error fetching bookings:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });

  }
};

// Get User Bookings
const getUserBookings = async (req, res) => {
  try {
    const bookings = await Booking.find({ user: req.user._id }).populate('property', 'propertyTitle');
    return res.status(200).json({ success: true, data: bookings });
  } catch (error) {
    console.error('Error fetching user bookings:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// Update Booking Status
const updateBookingStatus = async (req, res) => {
  const { bookingId, status } = req.body;

  // Validate input
  if (!bookingId || !status) {
    return res.status(400).json({ success: false, message: 'Booking ID and status are required' });
  }

  try {
    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({ success: false, message: 'Booking not found' });
    }

    booking.status = status;
    await booking.save();

    res.status(200).json({ success: true, message: 'Booking status updated successfully', booking });
  } catch (error) {
    console.error("Error updating booking status:", error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

//Update Payment Method
const updatePaymentMethod = async (req, res) => {
  const { bookingId, paymentMethod } = req.body;

  //Validate input
  if (!bookingId || !paymentMethod) {
    return res.status(400).json({ success: false, message: 'Booking ID and payment method are required' });
  }

  try {
    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({ success: false, message: 'Booking not found' });
    }
    booking.paymentMethod = paymentMethod;
    await booking.save();
    res.status(200).json({ success: true, message: 'Payment method updated successfully', booking });
  } catch (error) {
    console.error("Error updating payment method:", error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
}

module.exports = {
  createBooking,
  getAllBookings,
  updateBookingStatus,
  getUserBookings,
  updatePaymentMethod
};
