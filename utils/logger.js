
// ============================================================
// FORMAT DATE
// ============================================================

const getTimestamp = () => {
  return new Date().toISOString();
};

// ============================================================
// LOGGER
// ============================================================

const logger = {
  info(message, meta = null) {
    console.log(`[${getTimestamp()}] [INFO] ${message}`, meta || "");
  },

  warn(message, meta = null) {
    console.warn(`[${getTimestamp()}] [WARN] ${message}`, meta || "");
  },

  error(message, meta = null) {
    console.error(`[${getTimestamp()}] [ERROR] ${message}`, meta || "");
  },
};

module.exports = logger;
