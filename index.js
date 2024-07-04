import express from 'express';
import { connectToDb } from './config/db.js';
import userRoutes from './routes/user.routes.js';
import cors from 'cors'; // Import cors

const app = express();
const PORT = process.env.PORT || 7000;

// Connect to MongoDB database
connectToDb();

// Middleware
app.use(express.json());
app.use(cors()); // Enable CORS for all routes

// Routes
app.use('/api', userRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
    if (!err.statusCode) {
        err.statusCode = 500; 
    }
    res.status(err.statusCode).json({
        error: {
            statusCode: err.statusCode,
            message: err.message
        }
    });
});

// Default route
app.get('/', (req, res) => {
    res.send('Welcome to my User Registration and Login API!');
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
