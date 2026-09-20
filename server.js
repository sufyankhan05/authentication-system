const express = require("express");
const logger = require("./utils/logger");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const helmet = require("helmet");
const env = require("./config/env");
const connectDB = require("./config/db");
const errorMiddleware = require("./middleware/errorMiddleware");
const app = express();
connectDB();
const asyncHandler = require("./utils/asyncHandler");
const AppError = require("./utils/AppError");
// ==================================================
// MIDDLEWARE
// ==================================================
app.use(helmet());
app.use(express.json({ limit: "10kb" }));  // it means "Don't accept request bodies larger than this size."
app.use(express.urlencoded({ extended: true, limit: "10kb" }));
app.use(cookieParser());

const corsOptions = {
  origin: env.FRONTEND_URL,
  credentials: true,
};

app.use(cors(corsOptions));

// ==================================================
// ROUTES
// ==================================================

const authRoutes = require("./routes/authRoutes");

const userRoutes = require("./routes/userRoutes");


app.use("/api/auth", authRoutes);

app.use("/api/users", userRoutes);




// ==================================================
// HOME
// ==================================================

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Authentication API is running",
  });
});

//test
app.get("/test-async-error",asyncHandler(async (req, res)=>{
  throw new Error("Async error is working")
}))

app.get(
  "/test-async-app-error",
  asyncHandler(async (req, res) => {
    throw new AppError("Async AppError is working", 422);
  }),
);
// ==================================================
// 404
// ==================================================

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found",
  });
});

// Error middleware
app.use(errorMiddleware);

// ==================================================
// SERVER
// ==================================================

const PORT = env.PORT;

app.listen(PORT, () => {
  logger.info(
    `Server started at http://localhost:${PORT}`,
  );
});