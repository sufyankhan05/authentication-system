const mongoose = require("mongoose");

const env = require("./env");

const logger = require("../utils/logger");

const connectDB = async () => {
  try {
    const connection = await mongoose.connect(env.MONGODB_URI);

    logger.info(`MongoDB connected: ${connection.connection.host}`);
  } catch (error) {
    logger.error("MongoDB connection error", error.message);

    process.exit(1);
  }
};

module.exports = connectDB;
