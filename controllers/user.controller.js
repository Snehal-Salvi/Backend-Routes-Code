import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
import { errorHandler } from "../middleware/errorHandler.js";

// Register User
export const registerUser = async (req, res, next) => {
  try {
    const existingUser = await User.findOne({ email: req.body.email });
    if (existingUser) {
      throw errorHandler(400, "Email already exists");
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    const newUser = new User({
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword,
    });

    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    next(error);
  }
};

// Login User
// Login User
export const loginUser = async (req, res, next) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      throw errorHandler(401, "Invalid credentials");
    }

    const passwordMatch = await bcrypt.compare(
      req.body.password,
      user.password
    );

    if (!passwordMatch) {
      throw errorHandler(401, "Invalid credentials");
    }

    // Generate JWT token with _id included in payload
    const token = jwt.sign(
      { _id: user._id, email: user.email }, // Include _id in the payload
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Send token and user info in response
    const userInfo = {
      userId: user._id,
      username: user.username,
      email: user.email,
      profilePicture: user.profilePicture,
      isAdmin: user.isAdmin,
      isOauthUser: user.isOauthUser,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };

    res.status(200).json({ token, user: userInfo });
  } catch (error) {
    next(error);
  }
};

// Register Admin
export const registerAdmin = async (req, res, next) => {
  try {
    const existingUser = await User.findOne({ email: req.body.email });
    if (existingUser) {
      throw errorHandler(400, "Email already exists");
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    const newAdmin = new User({
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword,
      isAdmin: true, // Set isAdmin to true
    });

    await newAdmin.save();
    res.status(201).json({ message: "Admin user registered successfully" });
  } catch (error) {
    next(error);
  }
};

// getAllUsers
export const getAllUsers = async (req, res, next) => {
  try {
    const users = await User.find({}, "-password");

    res.status(200).json(users);
  } catch (error) {
    next(error);
  }
};

export const deleteUser = async (req, res, next) => {
  try {
    const userId = req.user._id;

    // Find the user by _id and delete
    const deletedUser = await User.findOneAndDelete({ _id: userId });

    if (!deletedUser) {
      throw errorHandler(404, "User not found");
    }

    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    next(error);
  }
};

// Update user
export const updateUser = async (req, res, next) => {
  try {
    const userId = req.user._id;

    // Destructure fields from req.body
    const { username, email, password, profilePicture } = req.body;

    // Find the user by _id
    const user = await User.findOne({ _id: userId });

    if (!user) {
      throw errorHandler(404, "User not found");
    }

    // Update user fields if provided in req.body
    if (username) {
      user.username = username;
    }
    if (email) {
      user.email = email;
    }
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      user.password = hashedPassword;
    }
    if (profilePicture) {
      user.profilePicture = profilePicture;
    }

    // Save updated user
    await user.save();

    // Return updated user data (excluding sensitive fields)
    const updatedUser = {
      userId: user._id,
      username: user.username,
      email: user.email,
      profilePicture: user.profilePicture,
      isAdmin: user.isAdmin,
      isOauthUser: user.isOauthUser,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };

    res.status(200).json(updatedUser);
  } catch (error) {
    next(error);
  }
};
