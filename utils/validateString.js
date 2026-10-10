const validateString = (value, fieldName, minLength = 1, maxLength = 100) => {
  if (value === undefined || value === null) {
    return {
      valid: false,
      message: `${fieldName} is required`,
    };
  }

  if (typeof value !== "string") {
    return {
      valid: false,
      message: `${fieldName} must be a string`,
    };
  }

  const trimmedValue = value.trim();

  if (trimmedValue.length < minLength) {
    return {
      valid: false,
      message: `${fieldName} must be at least ${minLength} characters long`,
    };
  }

  if (trimmedValue.length > maxLength) {
    return {
      valid: false,
      message: `${fieldName} must not exceed ${maxLength} characters`,
    };
  }

  return {
    valid: true,
    message: `${fieldName} is valid`,
  };
};

module.exports = validateString;
