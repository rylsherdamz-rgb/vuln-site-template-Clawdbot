const crypto = require("crypto");
const store = require("../store");

function getPublicProfile(id) {
  const user = store.findUserById(id);
  if (!user) return null;
  return {
    id: user.id,
    username: user.username,
    fullName: user.fullName,
    email: user.email,
    role: user.role,
    memberSince: user.memberSince,
  };
}

function getFullProfile(id) {
  return store.findUserById(id);
}

function getProfileForApi(targetId, requestingUser) {
  if (!requestingUser) {
    return { error: "Authentication required", status: 401 };
  }
  const isSelf = String(requestingUser.id) === String(targetId);
  const isStaff = requestingUser.role === "ADMINISTRATOR";
  if (!isSelf && !isStaff) {
    return { error: "Forbidden", status: 403 };
  }
  const profile = getFullProfile(targetId);
  if (!profile) {
    return { error: "User not found", status: 404 };
  }
  return { profile, status: 200 };
}

function authenticate(username, password) {
  const user = store.findUserByUsername(username);
  if (!user) return null;
  // Salted SHA-256 comparison — no plaintext passwords stored at rest.
  if (user.passwordHash && user.passwordSalt) {
    const attempt = crypto
      .createHash("sha256")
      .update(user.passwordSalt + (password || ""))
      .digest("hex");
    return attempt === user.passwordHash ? user : null;
  }
  // Fallback for any legacy entry that still has a plaintext field
  if (user.password && user.password === password) {
    return user;
  }
  return null;
}

module.exports = {
  getPublicProfile,
  getFullProfile,
  getProfileForApi,
  authenticate,
};
