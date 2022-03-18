// require dependencies
const mongoose = require("mongoose");
const dotenv = require("dotenv");
dotenv.config();
//  creating connection to database
const { DATABASE_URL } = process.env;

const connectDB = async () => {
  try {
    await mongoose.connect(DATABASE_URL, {
      useUnifiedTopology: true,
      useNewUrlParser: true,
    });
    console.log("server is up and running");
  } catch (error) {
    console.log("server is down");
  }
};
//   exporting modules
module.exports = connectDB();
