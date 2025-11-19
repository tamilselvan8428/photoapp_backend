// server.js
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cors = require('cors');
const dotenv = require('dotenv');
const MongoStore = require('connect-mongo');

dotenv.config();

const User = require('./models/User');
const Photo = require('./models/Photo');

const app = express();
const PORT = process.env.PORT || 5000;

// -----------------------------
// Trust proxy (required on Render/Heroku-like platforms)
// -----------------------------
if (process.env.NODE_ENV === 'production') {
  // Trust first proxy so secure cookies and req.protocol work behind load balancers
  app.set('trust proxy', 1);
}

// ========= MIDDLEWARE =========
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true }));

// -----------------------------
// FRONTEND ORIGIN CONFIG
// set FRONTEND_ORIGIN in env: e.g. https://photosgallary.netlify.app
// fallback local dev:
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';

// optional extra allowed dev origin
const EXTRA_DEV_ORIGIN = process.env.EXTRA_DEV_ORIGIN || null;

// ---------------------------------
// CORS - allow only the configured frontend origin(s)
// ---------------------------------
const allowedOrigins = [FRONTEND_ORIGIN];
if (EXTRA_DEV_ORIGIN) allowedOrigins.push(EXTRA_DEV_ORIGIN);

app.use(
  cors({
    origin: function (origin, callback) {
      // allow requests with no origin (e.g. mobile apps, curl, Postman)
      if (!origin) return callback(null, true);
      if (allowedOrigins.indexOf(origin) !== -1) {
        return callback(null, true);
      } else {
        return callback(new Error('CORS policy: This origin is not allowed: ' + origin));
      }
    },
    credentials: true,
  })
);

// ========= SESSION CONFIG =========
// Use secure cookies in production, otherwise lax for local dev
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'fallbacksecret',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      collectionName: 'sessions',
    }),
    cookie: {
      secure: process.env.NODE_ENV === 'production', // must be true on HTTPS
      httpOnly: true,
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    },
  })
);

// ========= PASSPORT =========
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// ========== GOOGLE STRATEGY ==========
if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.GOOGLE_CALLBACK_URL) {
  console.warn('Google OAuth env vars are missing. Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and GOOGLE_CALLBACK_URL.');
}

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
          user = await User.create({
            googleId: profile.id,
            displayName: profile.displayName,
            email: profile.emails?.[0]?.value,
            isVerified: true,
          });
        }
        return done(null, user);
      } catch (err) {
        console.error('Google strategy error:', err);
        return done(err, null);
      }
    }
  )
);

// ========= ROUTES =========

// healthcheck (useful to debug 502 / cold start)
app.get('/health', (req, res) => res.json({ ok: true, time: Date.now() }));

// ---------- GOOGLE AUTH ROUTES ----------
app.get(
  '/auth/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    prompt: 'select_account',
  })
);

// More robust callback handler that logs errors
app.get('/auth/google/callback', (req, res, next) => {
  passport.authenticate('google', (err, user, info) => {
    if (err) {
      console.error('Passport authenticate error:', err);
      // Redirect to frontend with error param
      const redirect = (process.env.FRONTEND_ORIGIN || FRONTEND_ORIGIN) + '/login?oauth=error';
      return res.redirect(redirect);
    }

    if (!user) {
      const redirect = (process.env.FRONTEND_ORIGIN || FRONTEND_ORIGIN) + '/login?oauth=fail';
      return res.redirect(redirect);
    }

    req.logIn(user, (loginErr) => {
      if (loginErr) {
        console.error('req.logIn error:', loginErr);
        const redirect = (process.env.FRONTEND_ORIGIN || FRONTEND_ORIGIN) + '/login?oauth=login_error';
        return res.redirect(redirect);
      }

      // success -> send user to frontend root
      return res.redirect(process.env.FRONTEND_ORIGIN || FRONTEND_ORIGIN);
    });
  })(req, res, next);
});

// ========= NORMAL AUTH ROUTES =========

// GET CURRENT USER
app.get('/api/current_user', (req, res) => {
  res.json({ user: req.user || null });
});

// LOGOUT
app.post('/api/logout', (req, res) => {
  // req.logout has callback in newer passport versions
  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ success: false });
    }
    // Also destroy session server-side
    req.session?.destroy?.(() => {
      res.clearCookie('connect.sid', { path: '/' });
      return res.json({ success: true });
    });
  });
});

// REGISTER
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
      isVerified: true,
    });
    await user.save();
    req.login(user, (err) => {
      if (err) {
        console.error('Registration login error:', err);
        return res.status(500).json({ message: 'Registration failed' });
      }
      return res.status(201).json({
        success: true,
        message: 'Registration successful',
        user: {
          id: user._id,
          email: user.email,
          displayName: user.displayName,
          isVerified: user.isVerified,
        },
      });
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Registration failed' });
  }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

    const user = await User.findOne({ email: email.toLowerCase().trim() }).select('+password');
    if (!user) return res.status(401).json({ message: 'Invalid email or password' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid email or password' });

    req.login(user, (err) => {
      if (err) {
        console.error('Login error:', err);
        return res.status(500).json({ message: 'Login failed' });
      }
      return res.json({
        success: true,
        message: 'Login successful',
        user: {
          id: user._id,
          email: user.email,
          displayName: user.displayName,
          isVerified: user.isVerified,
        },
      });
    });
  } catch (error) {
    console.error('Login catch error:', error);
    res.status(500).json({ message: 'Login failed' });
  }
});

// ========= PHOTO ROUTES =========

// UPLOAD PHOTO
app.post('/api/photos', async (req, res) => {
  try {
    const { title, description, imageBase64 } = req.body;
    if (!req.user?._id) return res.status(401).json({ error: 'Not authenticated' });
    const photo = await Photo.create({
      title,
      description,
      imageBase64,
      user: req.user._id,
    });
    res.json(photo);
  } catch (err) {
    console.error('Upload photo error:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET ALL PHOTOS FOR USER
app.get('/api/photos', async (req, res) => {
  try {
    if (!req.user?._id) return res.status(401).json({ error: 'Not authenticated' });
    const photos = await Photo.find({ user: req.user._id }).sort({ createdAt: -1 });
    res.json(photos);
  } catch (err) {
    console.error('Fetch photos error:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET PHOTO BY ID
app.get('/api/photos/:id', async (req, res) => {
  try {
    const photo = await Photo.findById(req.params.id);
    res.json(photo);
  } catch (err) {
    console.error('Get photo error:', err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE PHOTO
app.delete('/api/photos/:id', async (req, res) => {
  try {
    if (!req.user?._id) return res.status(401).json({ error: 'Not authenticated' });
    const photo = await Photo.findOne({ _id: req.params.id, user: req.user._id });
    if (!photo) return res.status(404).json({ error: 'Photo not found' });
    await Photo.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    console.error('Delete photo error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ========= DATABASE + SERVER START =========
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log('MongoDB Connected');
    app.listen(PORT, () => console.log(`Server running on ${PORT}`));
  })
  .catch((err) => {
    console.error('Mongo connect error:', err);
  });
