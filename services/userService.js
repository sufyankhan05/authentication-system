const User = require("../models/user");

const getUsers = async (query) => {
  const page = Math.max(
    Number.parseInt(query.page, 10) || 1,
    1,
  );

  const limit = Math.min(
    Math.max(
      Number.parseInt(query.limit, 10) || 10,
      1,
    ),
    100,
  );

  const skip = (page - 1) * limit;

  const filter = {};

  // Filter by role
  if (query.role) {
    const allowedRoles = ["user", "teacher", "admin"];

    if (!allowedRoles.includes(query.role)) {
      const error = new Error("Invalid role");
      error.statusCode = 400;
      throw error;
    }

    filter.role = query.role;
  }

  // Search
  if (query.search) {
    const search = query.search.trim();

    if (search.length > 100) {
      const error = new Error("Search query is too long");
      error.statusCode = 400;
      throw error;
    }

    filter.$or = [
      {
        name: {
          $regex: search,
          $options: "i",
        },
      },
      {
        email: {
          $regex: search,
          $options: "i",
        },
      },
    ];
  }

  // Sorting
  const sortQuery = query.sort || "-createdAt";

  const sortField = sortQuery.startsWith("-")
    ? sortQuery.slice(1)
    : sortQuery;

  const sortDirection = sortQuery.startsWith("-") ? -1 : 1;

  const allowedSortFields = [
    "name",
    "email",
    "role",
    "createdAt",
  ];

  if (!allowedSortFields.includes(sortField)) {
    const error = new Error("Invalid sort field");
    error.statusCode = 400;
    throw error;
  }

  const sort = {
    [sortField]: sortDirection,
  };

  // Database queries
  const [users, totalUsers] = await Promise.all([
    User.find(filter)
      .select(
        "_id name email role permissions isEmailVerified createdAt updatedAt",
      )
      .skip(skip)
      .limit(limit)
      .sort(sort),

    User.countDocuments(filter),
  ]);

  const totalPages = Math.ceil(totalUsers / limit);

  return {
    users,
    pagination: {
      page,
      limit,
      totalUsers,
      totalPages,
    },
  };
};

module.exports = {
  getUsers,
};