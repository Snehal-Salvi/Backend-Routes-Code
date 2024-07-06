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

//delete user
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

// Request Password Reset - Send OTP
export const forgotPassword = async (req, res, next) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      throw errorHandler(404, "User with this email not found");
    }

    // Generate OTP and set expiration time (1 hour)
    const otp = generateOTP();
    const otpExpires = Date.now() + 3600000; // 1 hour

    // Update user with OTP and expiration
    user.resetPasswordOTP = otp;
    user.resetPasswordExpires = otpExpires;
    await user.save();

    // Configure Nodemailer transporter
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASSWORD
      }
    });

    // Email options
    const mailOptions = {
      from: process.env.EMAIL_USERNAME,
      to: user.email,
      subject: 'Password Reset OTP',
      text: `Your password reset OTP is ${otp}. It is valid for 1 hour.`
    };

    // Send email with OTP
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return next(error);
      }
      res.status(200).json({ message: 'OTP sent to your email address' });
    });
  } catch (error) {
    next(error);
  }
};

// Reset Password using OTP
export const resetPassword = async (req, res, next) => {
  try {
    const { email, otp, newPassword } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      throw errorHandler(404, "User not found");
    }

    // Check if OTP is valid and not expired
    if (user.resetPasswordOTP !== otp || Date.now() > user.resetPasswordExpires) {
      throw errorHandler(400, "Invalid or expired OTP");
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password and clear the OTP fields
    user.password = hashedPassword;
    user.resetPasswordOTP = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    next(error);
  }
};
