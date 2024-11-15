const db = require("../middleware/db.controller");
const logger = require("../services/logger");

const registerUser = (req, res) => {
  const {
    firstName,
    lastName,
    hobbies,
    gender,
    email,
    password,
    phone,
    image,
  } = req.body;

  if (!firstName || !phone || !email || !password) {
    logger.log("error", "All field are required");
    return res.status(400).json({ message: "All fields are required" });
  }

  const query =
    "INSERT INTO users (firstName,lastName,hobbies,gender, email, password, phone, image) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

  db.query(
    query,
    [firstName, lastName, hobbies, gender, email, password, phone, image],
    (err, result) => {
      if (err) {
        console.error("Error inserting user:", err);
        return res.status(500).json({ message: "Error registering user" });
      }

      logger.log("info", "User register Successfully");
      return res.status(201).json({
        message: "User registered successfully",
        userId: result.insertId,
      });
    }
  );
};

module.exports = { registerUser };
