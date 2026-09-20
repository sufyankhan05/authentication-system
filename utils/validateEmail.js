const validateEmail = (email) => {
  if (email === undefined || email === null) {
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

  const cleanEmail = email.trim();

  if (cleanEmail.length === 0) {
    return {
      valid: false,
      message: "Email is required",
    };
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (!emailRegex.test(cleanEmail)) {
    return {
      valid: false,
      message: "Invalid email format",
    };
  }

  return {
    valid: true,
    message: "Valid email",
  };
};

module.exports = validateEmail;