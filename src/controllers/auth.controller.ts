import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import User from '../models/User';
import { generateToken } from '../utils/jwt';

// Signup with Email/Password
export const signup = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password, name } = req.body;
    
    // Validation
    if (!email || !password || !name) {
      res.status(400).json({
        success: false,
        message: 'Email, password, and name are required',
      });
      return;
    }
    
    // Check if user exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      res.status(400).json({
        success: false,
        message: 'Email already registered',
      });
      return;
    }
    
    // Hash password
    const password_hash = await bcrypt.hash(password, 12);
    
    // Create user
    const user = await User.create({
      email: email.toLowerCase(),
      name,
      auth: {
        provider: 'email',
        password_hash,
        email_verified: false,
      },
      role: 'user',
    });
    
    // Generate JWT
    const token = generateToken({
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
    });
    
    res.status(201).json({
      success: true,
      message: 'Account created successfully',
      data: {
        token,
        user: {
          id: user._id,
          email: user.email,
          name: user.name,
          role: user.role,
        },
      },
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during signup',
    });
  }
};

// Login with Email/Password
export const login = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;
    
    // Validation
    if (!email || !password) {
      res.status(400).json({
        success: false,
        message: 'Email and password are required',
      });
      return;
    }
    
    // Find user
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      res.status(401).json({
        success: false,
        message: 'Invalid email or password',
      });
      return;
    }
    
    // Check if email/password login
    if (user.auth.provider !== 'email' || !user.auth.password_hash) {
      res.status(400).json({
        success: false,
        message: 'Please login with Google',
      });
      return;
    }
    
    // Verify password
    const isPasswordValid = await bcrypt.compare(
      password,
      user.auth.password_hash
    );
    
    if (!isPasswordValid) {
      res.status(401).json({
        success: false,
        message: 'Invalid email or password',
      });
      return;
    }
    
    // Update last login
    user.last_login = new Date();
    await user.save();
    
    // Generate JWT
    const token = generateToken({
      userId: user._id.toString() as string,
      email: user.email,
      role: user.role,
    });
    
    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        token,
        user: {
          id: user._id,
          email: user.email,
          name: user.name,
          avatar: user.avatar,
          role: user.role,
          subscription: user.subscription,
        },
      },
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during login',
    });
  }
};

// // Get Current User
// export const getCurrentUser = async (
//   req: Request,
//   res: Response
// ): Promise<void> => {
//   try {
//     const user = await User.findById(req.user?.userId).select('-auth.password_hash');
    
//     if (!user) {
//       res.status(404).json({
//         success: false,
//         message: 'User not found',
//       });
//       return;
//     }
    
//     res.status(200).json({
//       success: true,
//       data: { user },
//     });
//   } catch (error) {
//     console.error('Get user error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Server error',
//     });
//   }
// };