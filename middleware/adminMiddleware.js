import User from '../models/user.model.js';
import { errorHandler } from '../middleware/errorHandler.js';

export const checkIsAdmin = async (req, res, next) => {
  try {
    // Find user by email from the decoded JWT token
    const user = await User.findOne({ email: req.user.email });
    if (!user || !user.isAdmin) {
      return next(errorHandler(403, 'Access denied. Admins only.'));
    }
    next();
  } catch (error) {
    next(error);
  }
};
