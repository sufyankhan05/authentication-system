const request = require("supertest");
const express = require("express");
const authorize = require("../middleware/roleMiddleware");

const app = express();

// Simulate a user who has already passed authentication.
// These tests focus only on role authorization.
app.use((req, res, next) => {
  req.user = global.testUser;
  next();
});

app.get("/admin", authorize("admin"), (req, res) => {
  res.status(200).json({
    success: true,
    message: "Admin access granted",
  });
});

beforeEach(() => {
  global.testUser = {
    _id: "test-user-id",
    role: "user",
  };
});

afterAll(() => {
  delete global.testUser;
});

describe("Role authorization", () => {
  test("normal user receives 403", async () => {
    const response = await request(app).get("/admin");

    expect(response.status).toBe(403);
    expect(response.body.success).toBe(false);
  });

  test("admin receives 200", async () => {
    global.testUser = {
      _id: "test-admin-id",
      role: "admin",
    };

    const response = await request(app).get("/admin");

    expect(response.status).toBe(200);
    expect(response.body.success).toBe(true);
    expect(response.body.message).toBe("Admin access granted");
  });
});