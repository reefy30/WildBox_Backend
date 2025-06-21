const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
    fullName: { type: String },
    email: { type: String, required: true, unique: true },
}, { timestamps: true });

module.exports = mongoose.model("User", UserSchema);