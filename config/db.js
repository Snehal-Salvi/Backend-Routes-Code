import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

const url = process.env.DB_URL;

export const connectToDb = async () => {
    try {
        await mongoose.connect(url, {
            // useNewUrlParser: true,
            // useUnifiedTopology: true
        });
        console.log("MongoDB connected");
    } catch (err) {
        console.error("Error connecting to MongoDB:", err);
    }
};
