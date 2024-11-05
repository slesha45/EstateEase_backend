const path = require('path')
const propertyModel = require('../models/propertyModels')
const fs = require('fs') //filesystem

const createProperty = async (req, res) => {

    //Check incoming data
    console.log(req.body)
    console.log(req.files)

    //Destructuring the body data(json)
    const {
        propertyTitle,
        propertyPrice,
        propertyCategory,
        propertyLocation,
    } = req.body;

    //Validation
    if (!propertyTitle || !propertyPrice || !propertyLocation || !propertyCategory) {
        return res.status(400).json({
            "success": false,
            "message": "Please enter all fields"
        })
    }

    //validate if there is image
    if (!req.files || !req.files.propertyImage) {
        return res.status(400).json({
            "success": false,
            "message": "Image not found"
        })
    }

    const { propertyImage } = req.files;

    //upload image

    //1. Generate new image nme(abc.png) -> (213456-abc.png)
    const imageName = `${Date.now()}-${propertyImage.name}`

    //2. Make an upload path(/path/upload -directory)
    const imageUploadPath = path.join(__dirname, `../public/property/${imageName}`)

    //3. Move to that directory(await, try-catch)
    try {
        await propertyImage.mv(imageUploadPath)
        // res.send("Image uploaded")

        //save to database
        const newProperty = new propertyModel({
            propertyTitle: propertyTitle,
            propertyPrice: propertyPrice,
            propertyCategory: propertyCategory,
            propertyLocation: propertyLocation,
            propertyImage: imageName
        })
        const property = await newProperty.save()
        res.status(201).json({
            "success": true,
            "message": "Property Created Successfully",
            "data": property
        })


    } catch (error) {
        console.log(error)
        res.status(500).json({
            "success": false,
            "message": "Internal server error",
            "error": error
        })
    }
    // res.send("Create property API is working...")
};

//Fetch all properties
const getAllProperty = async (req, res) => {

    //try catch
    try {
        const allProperty = await propertyModel.find({})
        res.status(201).json({
            "success": true,
            "message": "Property Fetched Successfully",
            "Property": allProperty
        })

    } catch (error) {
        console.log(error)
        res.status(500).json({
            "success": false,
            "message": "Internal server error",
            "error": error
        })
    }
    //send response
}

//fetch single property
const getSingleProperty = async (req, res) => {

    //get property id from URL (params)
    const propertyId = req.params.id;

    //find
    try {
        const property = await propertyModel.findById(propertyId)
        if (!property) {
            res.status(400).json({
                "success": false,
                "message": "No Property Found",
            })
        }

        property.views++;
        await property.save();

        res.status(201).json({
            "success": true,
            "message": "Property Fetched!",
            "property": property
        })

    } catch (error) {
        console.log(error)
        res.status(500).json({
            "success": false,
            "message": "Internal server error",
            "error": error
        })
    }
}

//delete property
const deleteProperty = async (req, res) => {
    try {
        await propertyModel.findByIdAndDelete(req.params.id)
        res.status(201).json({
            "success": true,
            "message": "Property deleted successfully!"
        })
    } catch (error) {
        console.log(error)
        res.status(500).json({
            "success": false,
            "message": "Internal server error",
            "error": error
        })
    }
}

const updateProperty = async (req, res) => {
    try {

        //if there is image
        if (req.files && req.files.propertyImage) {
            //destructuring 
            const { propertyImage } = req.files;

            //upload image to /public/property folder

            //1. Generate new image nme(abc.png) -> (213456-abc.png)
            const imageName = `${Date.now()}-${propertyImage.name}`

            //2. Make an upload path(/path/upload -directory)
            const imageUploadPath = path.join(__dirname, `../public/property/${imageName}`)

            //move to folder
            await propertyImage.mv(imageUploadPath)

            //req.params(id), req.body(updated data = pn,pp,pc,pd), req files(image)
            //add new field to req.body(propertyImage -> name)
            req.body.propertyImage = imageName; //image uploaded (generated name)

            //if image is uploaded and req.body is assigned
            if (req.body.propertyImage) {

                //finding existing property
                const existingProperty = await propertyModel.findById(req.params.id)

                //searching in the directory/folder
                const oldImagePath = path.join(__dirname, `../public/property/${existingProperty.propertyImage}`)

                //delete from filesystem
                fs.unlinkSync(oldImagePath)
            }
        }

        //update the data
        const updateProperty = await propertyModel.findByIdAndUpdate(req.params.id, req.body)
        res.status(201).json({
            success: true,
            message: "Property Updated!",
            property: updateProperty
        })

    } catch (error) {
        console.log(error)
        res.status(500).json({
            success: false,
            message: "Internal Server Error",
            error: error
        })
    }
}

//pagination
// const paginationProperty = async (req, res) => {

//     //page no
//     const pageNo = req.query.page || 1;

//     //result per page
//     const resultPerPage = 2;

//     try {

//         //Find all products, skip, limit
//         const property = await propertyModel.find({})
//             .skip((pageNo - 1) * resultPerPage)
//             .limit(resultPerPage)

//         //if page 6 is requested, result 0
//         if (property.length === 0) {
//             return res.status(400).json({
//                 "success": false,
//                 "message": "No property found!"
//             })
//         }
//         //response
//         res.status(201).json({
//             "success": true,
//             "message": "Property Fetched!",
//             "property": property
//         })

//     } catch (error) {
//         console.log(error)
//         res.status(500).json({
//             "success": false,
//             "message": "Internal Server Error!"
//         })
//     }
// }
const paginationProperty = async (req, res) => {
    try {
      // page no
      const PageNo = parseInt(req.query.page) || 1;
      // per page count
      const resultPerPage = parseInt(req.query.limit) || 2;
   
      // Search query
      const searchQuery = req.query.q || '';
      const sortOrder = req.query.sort || 'asc';
   
      const filter = {};
      if (searchQuery) {
        filter.propertyTitle = { $regex: searchQuery, $options: 'i' };
      }
   
      // Sorting
      const sort = sortOrder === 'asc' ? { propertyPrice: 1 } : { propertyPrice: -1 };
   
      // Find doctors with filters, pagination, and sorting
      const properties = await propertyModel
        .find(filter)
        .skip((PageNo - 1) * resultPerPage)
        .limit(resultPerPage)
        .sort(sort);
   
      // If the requested page has no results
      if (properties.length === 0) {
        return res.status(400).json({
          success: false,
          message: "No properties found",
        });
      }
   
      // Send response
      res.status(200).json({
        success: true,
        message: "properties fetched successfully",
        property: properties,
      });
    } catch (error) {
      console.log(error);
      res.status(500).json({
        success: false,
        message: "Internal server error",
        error: error,
      });
    }
  };
  const getPropertyCount = async (req, res) => {
    try {
      const propertyCount = await propertyModel.countDocuments({});
   
      res.status(200).json({
        success: true,
        message: 'property count fetched successfully',
        propertyCount: propertyCount,
      });
    } catch (error) {
      console.log(error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error,
      });
    }
  };

module.exports = {
    createProperty,
    getAllProperty,
    getSingleProperty,
    deleteProperty,
    updateProperty,
    paginationProperty,
    getPropertyCount,
};