import dotenv from 'dotenv';
dotenv.config();

export const PORT = process.env.PORT || 5000;
export const mongoDBURL = process.env.MONGODB_URI;
export const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
export const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
// add more as needed
