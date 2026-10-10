const Session = require("../models/session");

const cleanupSessions = async () => {
  try {
    const retentionDate = new Date(
      Date.now() - 30 * 24 * 60 * 60 * 1000
    );

    const result = await Session.deleteMany({
      $or: [
        {
          revokedAt: {
            $ne: null,
            $lt: retentionDate,
          },
        },
        {
          expiresAt: {
            $lt: retentionDate,
          },
        },
      ],
    });

    console.log(
      `Session cleanup completed. Deleted ${result.deletedCount} old sessions.`
    );
  } catch (error) {
    console.error(
      "Session cleanup error:",
      error
    );
  }
};

module.exports = cleanupSessions;