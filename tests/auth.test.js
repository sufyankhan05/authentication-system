
const request = require("supertest");
const app = require("../app");

describe("Authentication and authorization", () => {
  test("protected route rejects requests without a token", async () => {
    const response = await request(app)
      .get("/api/auth/me");

    expect(response.status).toBe(401);
    expect(response.body.success).toBe(false);
  });

  test("admin-only endpoint rejects requests without a token", async () => {
    const response = await request(app)
      .get("/api/users");

    expect(response.status).toBe(401);
    expect(response.body.success).toBe(false);
  });
});