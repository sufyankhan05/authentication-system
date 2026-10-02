const asyncHandler = require("../utils/asyncHandler");
const userService = require("../services/userService");

const getUsers = asyncHandler(async (req, res) => {
  const result = await userService.getUsers(req.query);

  return res.status(200).json({
    success: true,
    message: "Users fetched successfully",
    data: result,
  });
});
module.exports = { getUsers };
