const mysql = require("mysql");
const message = require("../utils/message");
require("dotenv").config();

const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});

connection.connect(function (err) {
  if (err) throw err;
  console.log(message.DATABASE_CONNECTION);
});

module.exports = connection;
