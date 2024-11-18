const express = require("express");
const router = express.Router();
const upload = require("../../services/multer");
const {
  registerUser,
  getUser,
  userLogin,
} = require("../../controller/userController");

router.get("/register", getUser);
router.post("/register", upload.single("image"), registerUser);
router.post("/login", userLogin);

module.exports = router;
