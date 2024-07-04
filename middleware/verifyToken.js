// Middleware to verify JWT token
import jwt from "jsonwebtoken";
import { errorHandler } from "../middleware/errorHandler.js";  

export const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"];

  if (!token) {
    return next(errorHandler(401, "Unauthorized: No token provided"));
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return next(errorHandler(401, "Unauthorized: Invalid token"));
    }

    req.user = decoded;

    next();
  });
};
