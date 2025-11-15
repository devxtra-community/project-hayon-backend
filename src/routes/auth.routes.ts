import express from 'express';
import passport from 'passport';
import { signup, login } from '../controllers/auth.controller';
import { authenticate } from '../middleware/auth.middleware';
import { generateToken } from '../utils/jwt';
import { console } from 'inspector';

const router = express.Router();


router.post('/signup', signup);
router.post('/login', login);

// Get current user
// router.get('/me', authenticate, getCurrentUser);

// Google OAuth Routes
router.get(
  '/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    session: false,
  })
);

router.get(
  '/google/callback',
  passport.authenticate('google', {
    session: false,
    failureRedirect: `${process.env.FRONTEND_URL}/login?error=google_auth_failed`,
  }),
  (req, res) => {
    try {
      const user = req.user as any;
      
      // Generate JWT
      const token = generateToken({
        userId: user._id.toString(),
        email: user.email,
        role: user.role,
      });

      console.log('user:',user );
      
      // Redirect to frontend with token
      res.redirect(`${process.env.FRONTEND_URL}/api/auth/callback?token=${token}`);
    } catch (error) {
      res.redirect(`${process.env.FRONTEND_URL}/login?error=token_generation_failed`);
    }
  }
);

export default router;