const express = require("express");
const app = express();
const path = require("path");

const helmet = require("helmet");
app.use(helmet());

require("dotenv").config();
app.use(express.static(path.join(__dirname, "app", "public")));

const cors = require("cors");
app.use(cors());

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

app.use(require("express-useragent").express());
app.use("/", require("./app/routes/router"));

app.use(require("./app/middleware/response"));
app.use(require("./app/middleware/error").handleJoiErrors);
app.use(require("./app/middleware/error").handleErrors);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
