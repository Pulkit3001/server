const generateToken = async (email) => {
  try {
    const secret = await getSecretFromDB();

    return crypto
      .createHmac("sha256", secret)
      .update(email)
      .digest("base64");
  } catch (error) {
    console.error("Token generation failed:", error.message);
    throw error; // ✅ Re-throw
  }
};
