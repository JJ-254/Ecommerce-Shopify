const ErrorHandler = require("../utils/ErrorHandler");
const catchAsyncErrors = require("./catchAsyncErrors");
const jwt = require("jsonwebtoken");
const User = require("../model/user");
const Shop = require("../model/shop");

// ✅ Check if user is authenticated
exports.isAuthenticated = catchAsyncErrors(async (req, res, next) => {
  let token;

  // 🟢 Check if token is in cookies
  if (req.cookies.token) {
    token = req.cookies.token;
    console.log("🟢 Token found in cookies:", token);
  } 
  // 🟢 Check if token is in Authorization header (Bearer token)
  else if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
    token = req.headers.authorization.split(" ")[1];
    console.log("🟢 Token found in Authorization header:", token);
  }

  // 🔴 No token found → Unauthorized
  if (!token) {
    console.log("🔴 No token provided. Unauthorized access.");
    return next(new ErrorHandler("Please login to continue", 401));
  }

  try {
    // 🔍 Verify the JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    console.log("✅ Decoded Token:", decoded);

    // 🔍 Find user in database
    req.user = await User.findById(decoded.id);
    if (!req.user) {
      console.log("🔴 User not found in database.");
      return next(new ErrorHandler("User not found", 401));
    }

    next(); // 🟢 Proceed to next middleware
  } catch (error) {
    console.log("🔴 Token verification failed:", error.message);
    return next(new ErrorHandler("Invalid or expired token", 401));
  }
});

// ✅ Check if seller is authenticated
exports.isSeller = catchAsyncErrors(async (req, res, next) => {
  let token;

  // Check for seller token in cookies
  if (req.cookies.seller_token) {
    token = req.cookies.seller_token;
    console.log("🟢 Seller Token found in cookies:", token);
  } 
  // Check for seller token in Authorization header
  else if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
    token = req.headers.authorization.split(" ")[1];
    console.log("🟢 Seller Token found in Authorization header:", token);
  }

  // 🔴 No token found
  if (!token) {
    console.log("🔴 No seller token provided. Unauthorized access.");
    return next(new ErrorHandler("Please login to continue", 401));
  }

  try {
    // 🔍 Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    console.log("✅ Decoded Seller Token:", decoded);

    // 🔍 Find seller in database
    req.seller = await Shop.findById(decoded.id);
    if (!req.seller) {
      console.log("🔴 Seller not found in database.");
      return next(new ErrorHandler("Seller not found", 401));
    }

    next();
  } catch (error) {
    console.log("🔴 Seller Token verification failed:", error.message);
    return next(new ErrorHandler("Invalid or expired seller token", 401));
  }
});

// ✅ Check if user is an Admin
exports.isAdmin = (...roles) => {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      console.log(`🔴 Access denied for role: ${req.user ? req.user.role : "No Role"}`);
      return next(new ErrorHandler(`${req.user?.role || "User"} cannot access this resource!`, 403));
    }
    next();
  };
};
