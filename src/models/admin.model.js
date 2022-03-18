//  require dependencies
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
// creating  admin Scheme
const adminSchema = new Schema(
  {
    firstName: {
      type: String,
      required: true,
      trim: true,
    },
    lastName: {
      type: String,
      required: true,
      trim: true,
    },
    phoneNumber: {
      type: Number,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      match: [
        /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
        "Please fill a valid email address",
      ],
    },
    password: {
      type: String,
      required: true,
      trim: true,
    },
    role: {
      type: String,
      enum: ["Admin"],
      default: "Admin",
    },
  },
  {
    timestamps: true,
  }
);

//    exporting modules
module.exports = mongoose.model("Admin", adminSchema);
