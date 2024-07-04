import express from "express";
import {
  registerUser,
  loginUser,
  registerAdmin,
  getAllUsers,
  deleteUser,
  updateUser,
} from "../controllers/user.controller.js";
import { verifyToken } from "../middleware/verifyToken.js";
import { checkIsAdmin } from "../middleware/adminMiddleware.js";

const router = express.Router();

// Public routes
router.post("/register", registerUser);
router.post("/login", loginUser);

// Admin registration route - protected
router.post("/register-admin", verifyToken, checkIsAdmin, registerAdmin);

// Protected route to get all users, only accessible by admin users
router.get("/users", verifyToken, checkIsAdmin, getAllUsers);

// Protected route to delete user's own account
router.delete("/delete-user", verifyToken, deleteUser);

// Protected route to edit user's own account
router.put("/update-user", verifyToken, updateUser);

export default router;
