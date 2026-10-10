
const swaggerJsdoc = require("swagger-jsdoc");

const options = {
  definition: {
    openapi: "3.0.0",

    paths: {
  "/": {
    get: {
      summary: "Check API status",
      responses: {
        "200": {
          description: "API is running",
        },
      },
    },
  },
},

    info: {
      title: "Authentication API",
      version: "1.0.0",
      description:
        "API documentation for the MERN authentication backend",
    },

    servers: [
      {
        url: "http://localhost:5000",
        description: "Local development server",
      },
    ],

    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
      },
    },
  },

  apis: [],
};

module.exports = swaggerJsdoc(options);