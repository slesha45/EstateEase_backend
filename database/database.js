const mongoose = require('mongoose')

const connectDatabase = () => {
    mongoose.connect(process.env.MONGODB_CLOUD).then(() => {
        console.log("Database connected!")
    })
}

//Exporting the function

module.exports = connectDatabase