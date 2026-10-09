
const express = require("express");
const request = require("supertest");

const app = express();
app.use(express.json());

app.post("/register", (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({
      success: false,
      message: "Name, email and password are required",
    });
  }

  if (!email.includes("@")) {
    return res.status(400).json({
      success: false,
      message: "Invalid email address",
    });
  }

  return res.status(201).json({
    success: true,
    message: "Registration input is valid",
  });
});

describe("Request validation", () => {
  test("rejects missing required fields", async () => {
    const response = await request(app)
      .post("/register")
      .send({ name: "Test User" });

    expect(response.status).toBe(400);
    expect(response.body.success).toBe(false);
  });

  test("rejects invalid email", async () => {
    const response = await request(app)
      .post("/register")
      .send({
        name: "Test User",
        email: "invalid-email",
        password: "ExamplePassword123!",
      });

    expect(response.status).toBe(400);
  });

  test("accepts valid input", async () => {
    const response = await request(app)
      .post("/register")
      .send({
        name: "Test User",
        email: "test@example.com",
        password: "ExamplePassword123!",
      });

    expect(response.status).toBe(201);
    expect(response.body.success).toBe(true);
  });
});