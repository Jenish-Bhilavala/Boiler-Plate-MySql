const express = require("express");
const app = express();
const path = require("path");

const helmet = require("helmet");
app.use(helmet());

require("dotenv").config();
app.use(express.static(path.join(__dirname, "public")));

const cors = require("cors");
app.use(cors());

const bodyParser = require("body-parser");
app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({ limit: "50mb", extended: true }));

app.use("/api/users", require("./app/routes/route/user"));

app.use(require("./app/middleware/response"));
app.use(require("./app/middleware/error").handleJoiErrors);
app.use(require("./app/middleware/error").handleErrors);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on ${PORT}`));

// wiston and multer, emial /services
