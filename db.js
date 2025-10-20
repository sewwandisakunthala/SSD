import mongoose from 'mongoose';

const MONGODB_URI = process.env.mongoDBURL
if (!MONGODB_URI) throw new Error('Missing MONGODB_URI / DB_URI');

let cached = global._mongoose;
if (!cached) cached = global._mongoose = { conn: null, promise: null };

export async function connectDB() {
    if (cached.conn) return cached.conn;
    if (!cached.promise) {
        cached.promise = mongoose.connect(MONGODB_URI).then((m) => m);
    }
    cached.conn = await cached.promise;
    return cached.conn;
}
