const multer = require("multer");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Make sure the 'uploads' folder exists, otherwise create it
    const uploadPath = path.join(__dirname, "../public/uploads");
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    // Generate a random filename using crypto
    crypto.randomBytes(12, function (err, bytes) {
      if (err) {
        return cb(err);
      }
      const fn = bytes.toString("hex") + path.extname(file.originalname);
      cb(null, fn);
    });
  },
});

const upload = multer({ storage });

module.exports = upload;
