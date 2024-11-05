const mongoose = require('mongoose')

const propertySchema = new mongoose.Schema({
    propertyTitle: {
        type: String,
        required: true
    },
    propertyPrice: {
        type: Number,
        required: true
    },
    propertyCategory: {
        type: String,
        required: true,
    },
    propertyLocation: {
        type: String,
        required: true
    },
    propertyImage: {
        type: String,   
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now()
    },
    views: {
        type: Number,
        default: 0
    }
})

const Property = mongoose.model('properties', propertySchema)
module.exports = Property;