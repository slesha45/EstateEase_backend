const request = require('supertest');
const app = require('../index');
const mongoose = require('mongoose');
const path = require('path');

// Test tokens (use valid tokens for testing)
const userToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY2OTY2NzBjOTY4YTRjNDVlZGE2MTZlZCIsImlhdCI6MTcyMzM2NDU1NH0.NFMTk2DQXya8D_Ip9Rk--9EeuX4iwQXgLeQlKTOypWE';
const invalidToken = 'invalidTokenHere';

let propertyId = '66b87ad6cecf582978293842'; // Existing property ID for testing

beforeAll(async () => {
    // Connect to the test database
    await mongoose.connect(process.env.MONGODB_CLOUD, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    });
});

afterAll(async () => {
    // Close the database connection after tests
    await mongoose.connection.close();
});

describe('Property API Tests', () => {

    // Test for creating a new property
    it('POST /api/property/create | Should create a new property', async () => {
        const response = await request(app)
            .post('/api/property/create')
            .set('Authorization', `Bearer ${userToken}`)
            .field('propertyTitle', 'Test Property')
            .field('propertyPrice', 50000)
            .field('propertyCategory', 'Apartment')
            .field('propertyLocation', 'New York')
            .attach('propertyImage', path.join(__dirname, 'sample_image.jpg'));

        expect(response.statusCode).toBe(201);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toEqual('Property Created Successfully');
        expect(response.body.data).toHaveProperty('_id');

        // Store propertyId for further tests
        propertyId = response.body.data._id;
    });

    // Test for fetching all properties
    it('GET /api/property/get_all_property | Should fetch all properties', async () => {
        const response = await request(app)
            .get('/api/property/get_all_property')
            .set('Authorization', `Bearer ${userToken}`);

        expect(response.statusCode).toBe(201);
        expect(response.body.success).toBe(true);
        expect(Array.isArray(response.body.Property)).toBe(true);
    });
    
    // Test for deleting a property by ID
    it('DELETE /api/property/delete_property/:id | Should delete a property by ID', async () => {
        const response = await request(app)
            .delete(`/api/property/delete_property/${propertyId}`)
            .set('Authorization', `Bearer ${userToken}`);

        expect(response.statusCode).toBe(201);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toEqual('Property deleted successfully!');
    });

    // Test for fetching properties with pagination
    it('GET /api/property/pagination?page=1&limit=2 | Should fetch paginated properties', async () => {
        const response = await request(app).get('/api/property/pagination?page=1&limit=2');

        expect(response.statusCode).toBe(200);
        expect(response.body.success).toBe(true);
        expect(Array.isArray(response.body.property)).toBe(true);
    });

    // Test for fetching property count
    it('GET /api/property/get_property_count | Should return the count of properties', async () => {
        const response = await request(app).get('/api/property/get_property_count');

        expect(response.statusCode).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body).toHaveProperty('propertyCount');
    });

    // Test for creating a property with missing fields
    it('POST /api/property/create | Should fail with missing fields', async () => {
        const response = await request(app)
            .post('/api/property/create')
            .set('Authorization', `Bearer ${userToken}`)
            .field('propertyTitle', 'Test Property');

        expect(response.statusCode).toBe(400);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toEqual('Please enter all fields');
    });

    // Test for creating a property with missing image
    it('POST /api/property/create | Should fail with missing image', async () => {
        const response = await request(app)
            .post('/api/property/create')
            .set('Authorization', `Bearer ${userToken}`)
            .field('propertyTitle', 'Test Property')
            .field('propertyPrice', 200000)
            .field('propertyCategory', 'Apartment')
            .field('propertyLocation', 'New York');

        expect(response.statusCode).toBe(400);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toEqual('Image not found');
    });

    // Test for fetching a single property with an invalid ID
    it('GET /api/property/get_single_property/:id | Should fail with invalid property ID', async () => {
        const response = await request(app)
            .get('/api/property/get_single_property/invalidPropertyId')
            .set('Authorization', `Bearer ${userToken}`);

        expect(response.statusCode).toBe(500);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toEqual('Internal server error');
    });

    // Test for deleting a property with an invalid ID
    it('DELETE /api/property/delete_property/:id | Should fail with invalid property ID', async () => {
        const response = await request(app)
            .delete(`/api/property/delete_property/invalidPropertyId`)
            .set('Authorization', `Bearer ${userToken}`);

        expect(response.statusCode).toBe(500);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toEqual('Internal server error');
    });

    // Test for fetching properties with pagination and no results
    it('GET /api/property/pagination?page=1000&limit=2 | Should return no properties', async () => {
        const response = await request(app).get('/api/property/pagination?page=1000&limit=2');

        expect(response.statusCode).toBe(400);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toEqual('No properties found');
    });

    // Test for fetching a single property without authorization
    it('GET /api/property/get_single_property/:id | Should fail without authorization', async () => {
        const response = await request(app)
            .get(`/api/property/get_single_property/${propertyId}`);

        expect(response.statusCode).toBe(400);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toEqual('Please login first');
    });

    // Test for fetching a single property with an invalid token
    it('GET /api/property/get_single_property/:id | Should fail with invalid token', async () => {
        const response = await request(app)
            .get(`/api/property/get_single_property/${propertyId}`)
            .set('Authorization', `Bearer ${invalidToken}`);

        expect(response.statusCode).toBe(400);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toEqual('Not Authenticated!');
    });

    // Test for updating a property with an invalid token
    it('PUT /api/property/update_property/:id | Should fail with invalid token', async () => {
        const response = await request(app)
            .put(`/api/property/update_property/${propertyId}`)
            .set('Authorization', `Bearer ${invalidToken}`)
            .field('propertyTitle', 'Invalid Token Update');

        expect(response.statusCode).toBe(400);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toEqual('Not Authenticated!');
    });

    // Test for deleting a property with an invalid token
    it('DELETE /api/property/delete_property/:id | Should fail with invalid token', async () => {
        const response = await request(app)
            .delete(`/api/property/delete_property/${propertyId}`)
            .set('Authorization', `Bearer ${invalidToken}`);

        expect(response.statusCode).toBe(400);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toEqual('Not Authenticated!');
    });
});