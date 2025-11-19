const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cors = require('cors');
const dotenv = require('dotenv');
dotenv.config();
const User = require('./models/User');
const Photo = require('./models/Photo');
const app = express();
const PORT = process.env.PORT || 5000;
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true }));
const allowedOrigins = [
  "https://photosgallary.netlify.app",
  "https://spectacular-genie-15822e.netlify.app"
];

app.options('*', cors());

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      let user = await User.findOne({ googleId: profile.id });

      if (!user) {
        user = await User.create({
          googleId: profile.id,
          displayName: profile.displayName,
          email: profile.emails[0].value,
        });
      }

      return done(null, user);
    }
  )
);
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);
app.get('/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: process.env.FRONTEND_ORIGIN + '/login'
  }),
  (req, res) => {
    res.redirect(process.env.FRONTEND_ORIGIN);
  }
);
app.get('/api/current_user', (req, res) => {
  res.json({ user: req.user || null });
});
app.post('/api/logout', (req, res) => {
  req.logout(() => {
    res.json({ success: true });
  });
});
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, displayName } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already in use' });
    }
    const user = new User({
      email: email.toLowerCase().trim(),
      password,
      displayName: displayName || email.split('@')[0],
      isVerified: true
    });

    await user.save();
    req.login(user, (err) => {
      if (err) {
        console.error('Login error:', err);
        return res.status(500).json({ message: 'Registration failed' });
      }
      res.status(201).json({
        success: true,
        message: 'Registration successful',
        user: {
          id: user._id,
          email: user.email,
          displayName: user.displayName,
          isVerified: user.isVerified
        }
      });
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Registration failed. Please try again.' 
    });
  }
});
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    const user = await User.findOne({ email: email.toLowerCase().trim() }).select('+password');
    
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    req.login(user, (err) => {
      if (err) {
        console.error('Login error:', err);
        return res.status(500).json({ message: 'Login failed' });
      }
      res.json({
        success: true,
        message: 'Login successful',
        user: {
          id: user._id,
          email: user.email,
          displayName: user.displayName,
          isVerified: user.isVerified
        }
      });
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Login failed. Please try again.' 
    });
  }
});
app.post('/api/photos', async (req, res) => {
  try {
    const { title, description, imageBase64 } = req.body;
    const userId = req.user?._id;
    
    if (!userId) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const photo = await Photo.create({ 
      title, 
      description, 
      imageBase64,
      user: userId 
    });
    
    res.json(photo);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.get('/api/photos', async (req, res) => {
  try {
    if (!req.user?._id) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const photos = await Photo.find({ user: req.user._id }).sort({ createdAt: -1 });
    res.json(photos);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.get('/api/photos/:id', async (req, res) => {
  const photo = await Photo.findById(req.params.id);
  res.json(photo);
});
app.delete('/api/photos/:id', async (req, res) => {
  try {
    if (!req.user?._id) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const photo = await Photo.findOne({ _id: req.params.id, user: req.user._id });
    
    if (!photo) {
      return res.status(404).json({ error: 'Photo not found or not authorized' });
    }

    await Photo.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log('MongoDB Connected');
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch((err) => console.log(err));
