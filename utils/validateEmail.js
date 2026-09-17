const validateEmail = (email) => {
  if (!email) {
    return {
      valid: false,
      message: "Email is required",
    };
  }

  if (typeof email !== "string") {
    return {
      valid: false,
      message: "Email must be a string",
    };
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (!emailRegex.test(email)) {
    return {
      valid: false,
      message: "Invalid email format",
    };
  }

  return {
    valid: true,
  };
};

module.exports = validateEmail;