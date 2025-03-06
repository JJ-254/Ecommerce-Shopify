const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "Please enter your name!"],
  },
  email: {
    type: String,
    required: [true, "Please enter your email!"],
    unique: true, // Ensuring unique emails
  },
  password: {
    type: String,
    required: [true, "Please enter your password"],
    minLength: [4, "Password should be greater than 4 characters"],
    select: false, // Prevents password from being retrieved by default
  },
  phoneNumber: {
    type: Number,
  },
  addresses: [
    {
      country: {
        type: String,
      },
      city: {
        type: String,
      },
      address1: {
        type: String,
      },
      address2: {
        type: String,
      },
      zipCode: {
        type: Number,
      },
      addressType: {
        type: String,
      },
    },
  ],
  role: {
    type: String,
    default: "user",
  },
  avatar: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now(),
  },
  resetPasswordToken: String,
  resetPasswordTime: Date,
});

// ✅ Fix: Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next(); // Prevent unnecessary hashing

  try {
    console.log("🔐 Hashing Password for:", this.email);
    this.password = await bcrypt.hash(this.password, 10);
    console.log("✅ Hashed Password Successfully!");
    next();
  } catch (error) {
    console.error("🚨 Error Hashing Password:", error);
    next(error);
  }
});

// ✅ Fix: Compare hashed password correctly with logging
userSchema.methods.comparePassword = async function (enteredPassword) {
  if (!this.password) {
    console.log("❌ No stored password found for user:", this.email);
    return false;
  }

  console.log("🔍 Comparing Passwords...");
  console.log("🔐 Entered Password:", enteredPassword);
  console.log("🔐 Stored Hashed Password:", this.password);

  try {
    const isMatch = await bcrypt.compare(enteredPassword, this.password);
    console.log("🔍 Password Match Result:", isMatch);
    return isMatch;
  } catch (error) {
    console.error("🚨 Error in bcrypt.compare:", error);
    return false;
  }
};

// ✅ Fix: JWT token generation with default expiration
userSchema.methods.getJwtToken = function () {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET_KEY, {
    expiresIn: process.env.JWT_EXPIRES || "7d", // Default to 7 days if not set
  });
};

module.exports = mongoose.model("User", userSchema);
