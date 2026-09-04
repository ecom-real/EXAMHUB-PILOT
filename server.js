require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { GoogleGenAI } = require('@google/genai');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');

// Initialize Gemini Client
const ai = process.env.GEMINI_API_KEY ? new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY }) : null;
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 15 * 1024 * 1024 } }); // 15MB memory limit

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// ── Supabase Client (server-side, uses service role key) ──────────────────────
const supabaseUrl = process.env.SUPABASE_URL || 'https://placeholder.supabase.co';
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || 'placeholder-service-key';
const anonKey = process.env.SUPABASE_ANON_KEY || 'placeholder-anon-key';

if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
  console.error('\n❌  Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in environment variables\n');
}

const supabase = createClient(supabaseUrl, serviceKey, {
  auth: { autoRefreshToken: false, persistSession: false }
});

const supabaseAuthClient = createClient(supabaseUrl, anonKey, {
  auth: { autoRefreshToken: false, persistSession: false }
});

// ── Rate Limiting ─────────────────────────────────────────────────────────────
// General API: 200 requests per minute per IP
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please slow down.' }
});

// Auth routes: 100 attempts per 15 minutes (brute-force protection)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again after 15 minutes.' }
});

// PDF parse: 5 per minute (Gemini calls are expensive)
const pdfLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many PDF uploads. Please wait a moment.' }
});

// ── Allowed Origins (set CORS_ORIGINS env var as comma-separated list) ────────
// In production (Netlify/Vercel), set CORS_ORIGINS to your deployed domain.
// If CORS_ORIGINS is not set, allow all origins (open) — needed when the
// API and frontend share the same Netlify domain (same-origin requests).
const allowedOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',').map(o => o.trim())
  : null; // null = allow all origins

// Middleware
app.use(helmet({
  contentSecurityPolicy: false // disabled to avoid breaking inline scripts in HTML pages
}));
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (server-to-server, curl, Postman, same-origin)
    if (!origin) return callback(null, true);
    // If no allowedOrigins configured, permit all
    if (!allowedOrigins) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));
app.use(express.json({ limit: '5mb' }));
app.use('/api', apiLimiter);                        // apply general limit to all /api routes
app.use('/api/questions/parse-pdf', pdfLimiter);    // limit Gemini PDF calls
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth Middleware ────────────────────────────────────────────────────────────
async function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    // Validate token by asking Supabase Auth directly — avoids Base64/secret issues
    const { data: { user: authUser }, error: authErr } = await supabase.auth.getUser(token);
    if (authErr || !authUser) {
      const msg = authErr?.message || '';
      if (msg.includes('expired') || msg.includes('JWT expired')) {
        return res.status(401).json({ error: 'Token expired' });
      }
      return res.status(401).json({ error: 'Authentication failed' });
    }

    // Get user profile (role etc.)
    const { data: profile } = await supabase.from('users').select('*').eq('id', authUser.id).single();
    req.user = { id: authUser.id, ...profile };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Authentication failed' });
  }
}

async function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

// ── Expose Supabase config to authenticated users only ───────────────────────
// Note: The anon key is designed to be public, but we gate it behind auth
// so that only logged-in users can query Supabase if ever needed client-side.
app.get('/api/config', authenticate, (req, res) => {
  res.json({ supabaseUrl, supabaseAnonKey: anonKey });
});

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// Register new student
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password, roll_number, phone, dob, gender } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password required' });

    // Create Supabase auth user
    const { data: authData, error: authErr } = await supabase.auth.admin.createUser({
      email, password,
      email_confirm: true,
      user_metadata: { name, role: 'student' }
    });
    if (authErr) return res.status(400).json({ error: authErr.message });

    // Update profile with extra fields
    await supabase.from('users').update({ name, roll_number, phone, dob, gender }).eq('id', authData.user.id);

    // Sign in to get token
    const { data: signIn, error: signInErr } = await supabaseAuthClient.auth.signInWithPassword({ email, password });
    if (signInErr) return res.status(400).json({ error: signInErr.message });

    const { data: profile } = await supabase.from('users').select('*').eq('id', authData.user.id).single();
    res.json({ token: signIn.session.access_token, user: profile });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

    const { data, error } = await supabaseAuthClient.auth.signInWithPassword({ email, password });
    if (error) return res.status(400).json({ error: 'Invalid email or password' });

    const { data: profile, error: profileErr } = await supabase.from('users').select('*').eq('id', data.user.id).single();

    if (profileErr || !profile) {
      console.error('Login profile fetch error:', profileErr?.message || 'Profile not found for user ' + data.user.id);
      return res.status(500).json({ error: 'User profile not found. Please contact the administrator.' });
    }

    if (!profile.is_active) return res.status(403).json({ error: 'Account is deactivated. Contact admin.' });

    res.json({ token: data.session.access_token, user: profile });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Get current user
app.get('/api/auth/me', authenticate, (req, res) => res.json({ user: req.user }));

// ═══════════════════════════════════════════════════════════════════════════════
// ADMIN - STUDENT MANAGEMENT ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// Get all students
app.get('/api/admin/students', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select('*').eq('role', 'student').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Update student details
app.put('/api/admin/students/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { branch, batch, semester, section, roll_number, name } = req.body;
    const { data, error } = await supabase.from('users').update({ branch, batch, semester, section, roll_number, name }).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Toggle student status
app.put('/api/admin/students/:id/status', authenticate, requireAdmin, async (req, res) => {
  try {
    const { is_active } = req.body;
    const { data, error } = await supabase.from('users').update({ is_active }).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Bulk Import Students via CSV (Simplified)
app.post('/api/admin/students/bulk-import', authenticate, requireAdmin, async (req, res) => {
  try {
    const students = req.body.students; // Array of objects parsed by frontend
    if (!Array.isArray(students)) return res.status(400).json({ error: 'Expected an array of students' });

    let imported = 0;
    let errors = [];

    for (const student of students) {
      try {
        // Create Supabase auth user
        const { data: authData, error: authErr } = await supabase.auth.admin.createUser({
          email: student.email,
          // Generate a random secure password if none provided
          password: student.password || Math.random().toString(36).slice(-8) + Math.random().toString(36).slice(-8).toUpperCase() + '!9',
          email_confirm: true,
          user_metadata: { name: student.name, role: 'student' }
        });

        if (authErr) { errors.push(`Email ${student.email}: ${authErr.message}`); continue; }

        // Update profile
        await supabase.from('users').update({
          name: student.name,
          roll_number: student.roll_number,
          branch: student.branch,
          batch: student.batch,
          semester: student.semester,
          section: student.section
        }).eq('id', authData.user.id);

        imported++;
      } catch (err) {
        errors.push(`Email ${student.email}: ${err.message}`);
      }
    }

    res.json({ success: true, imported, errors });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// EXAM ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// List exams
app.get('/api/exams', authenticate, async (req, res) => {
  try {
    let query = supabase.from('exams').select('*, exam_sections(*)');
    if (req.user.role !== 'admin') query = query.eq('is_published', true);
    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get single exam
app.get('/api/exams/:id', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase.from('exams')
      .select('*, exam_sections(*)')
      .eq('id', req.params.id)
      .single();
    if (error || !data) return res.status(404).json({ error: 'Exam not found' });
    if (req.user.role !== 'admin' && !data.is_published) return res.status(403).json({ error: 'Exam not available' });
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Allowed fields for exam create/update (whitelist to prevent injection of unexpected columns)
// Core fields always present in schema:
const EXAM_CORE_FIELDS = [
  'title', 'exam_code', 'description', 'instructions',
  'total_duration', 'total_marks', 'pass_percentage',
  'is_published', 'shuffle_questions', 'shuffle_options',
  'show_result', 'price'
];
// Optional fields that may not exist yet if migration hasn't been run:
const EXAM_OPTIONAL_FIELDS = ['enable_certificate', 'exam_type'];
const EXAM_ALLOWED_FIELDS = [...EXAM_CORE_FIELDS, ...EXAM_OPTIONAL_FIELDS];

function pickExamFields(body, exclude = []) {
  return EXAM_ALLOWED_FIELDS.reduce((acc, k) => {
    if (k in body && !exclude.includes(k)) acc[k] = body[k];
    return acc;
  }, {});
}

// Helper: run a Supabase query and, if it fails with a missing-column error (PGRST204),
// automatically retry without the optional columns that caused it.
async function safeExamQuery(queryFn) {
  let { data, error } = await queryFn([]);  // first try: all fields, no exclusions
  if (error && error.code === 'PGRST204') {
    // Strip optional columns and retry
    console.warn('safeExamQuery: missing optional exam columns, retrying without them:', EXAM_OPTIONAL_FIELDS);
    ({ data, error } = await queryFn(EXAM_OPTIONAL_FIELDS));
  }
  return { data, error };
}

// Create exam (admin)
app.post('/api/exams', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await safeExamQuery((exclude) =>
      supabase.from('exams').insert({
        ...pickExamFields(req.body, exclude),
        created_by: req.user.id
      }).select().single()
    );
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Update exam (admin)
app.put('/api/exams/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await safeExamQuery((exclude) =>
      supabase.from('exams').update(pickExamFields(req.body, exclude)).eq('id', req.params.id).select().single()
    );
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Delete exam (admin)
app.delete('/api/exams/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { error } = await supabase.from('exams').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Allowed fields for sections (whitelist)
const SECTION_ALLOWED_FIELDS = ['name', 'description', 'duration', 'marks_per_q', 'negative_marks', 'sort_order'];
function pickSectionFields(body) {
  return SECTION_ALLOWED_FIELDS.reduce((acc, k) => {
    if (k in body) acc[k] = body[k];
    return acc;
  }, {});
}

// ── Sections ──────────────────────────────────────────────────────────────────
app.get('/api/exams/:examId/sections', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase.from('exam_sections').select('*').eq('exam_id', req.params.examId).order('sort_order');
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/exams/:examId/sections', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('exam_sections').insert({ ...pickSectionFields(req.body), exam_id: req.params.examId }).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/sections/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('exam_sections').update(pickSectionFields(req.body)).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/sections/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { error } = await supabase.from('exam_sections').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// QUESTION ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// Get questions for admin (with answers)
app.get('/api/questions', authenticate, requireAdmin, async (req, res) => {
  try {
    let query = supabase.from('questions').select('*, options(*), numeric_answers(*)');
    if (req.query.examId) query = query.eq('exam_id', req.query.examId);
    if (req.query.sectionId) query = query.eq('section_id', req.query.sectionId);
    const { data, error } = await query.order('sort_order');
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get questions for student (no correct answers)
app.get('/api/exam-questions/:examId', authenticate, async (req, res) => {
  try {
    const { data: questions, error } = await supabase.from('questions')
      .select('*, options(id, content, sort_order), exam_sections(id, name)')
      .eq('exam_id', req.params.examId)
      .order('sort_order');
    if (error) throw error;

    // Shuffle if needed
    const { data: exam } = await supabase.from('exams').select('shuffle_questions, shuffle_options').eq('id', req.params.examId).single();
    let qs = questions;
    if (exam?.shuffle_questions) qs = qs.sort(() => Math.random() - 0.5);
    if (exam?.shuffle_options) {
      qs = qs.map(q => ({ ...q, options: q.options?.sort(() => Math.random() - 0.5) || [] }));
    }
    // Sort options by sort_order if not shuffled
    if (!exam?.shuffle_options) {
      qs = qs.map(q => ({ ...q, options: (q.options || []).sort((a, b) => a.sort_order - b.sort_order) }));
    }
    res.json(qs);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Create question (admin)
app.post('/api/questions', authenticate, requireAdmin, async (req, res) => {
  try {
    const { options: optData, numeric_answer, ...qData } = req.body;
    const { data: question, error: qErr } = await supabase.from('questions').insert(qData).select().single();
    if (qErr) throw qErr;

    // Insert options for MCQ/MSQ
    if (optData?.length && (qData.type === 'mcq' || qData.type === 'msq')) {
      const opts = optData.map((o, i) => ({ question_id: question.id, content: o.content, is_correct: o.is_correct, sort_order: i + 1 }));
      await supabase.from('options').insert(opts);
    }
    // Insert numeric answer
    if (numeric_answer !== undefined && qData.type === 'numeric') {
      await supabase.from('numeric_answers').insert({ question_id: question.id, correct_value: numeric_answer.correct_value, tolerance: numeric_answer.tolerance || 0 });
    }

    const { data: full } = await supabase.from('questions').select('*, options(*), numeric_answers(*)').eq('id', question.id).single();
    res.json(full);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Parse PDF using Gemini (admin) - Serverless compatible with memory storage
app.post('/api/questions/parse-pdf', authenticate, requireAdmin, upload.single('pdf'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No PDF file uploaded' });
    console.log('Received PDF upload:', req.file.originalname, 'Size:', req.file.size);
    if (!ai) return res.status(500).json({ error: 'GEMINI_API_KEY is not configured in .env' });

    const prompt = `You are an expert exam parser. Analyze this PDF and extract all questions, options, and answers.
Return the result strictly as a JSON array of objects with this structure:
[{
  "content": "Question text here",
  "type": "mcq" | "msq" | "subjective" | "numeric",
  "marks": 1,
  "difficulty": "easy" | "medium" | "hard",
  "options": [
    { "content": "Option text", "is_correct": true | false }
  ]
}]
Infer the "type" accurately: if multiple options are correct, it's "msq". If it has options but only 1 is correct, it's "mcq". If it requires a typed answer, it's "subjective" or "numeric".
Do not include markdown codeblocks (\`\`\`json) in your response, just return the raw JSON array.`;

    console.log('Generating content with gemini-2.5-flash using memory buffer...');
    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: [
        { inlineData: { data: req.file.buffer.toString('base64'), mimeType: req.file.mimetype || 'application/pdf' } },
        { text: prompt }
      ]
    });
    console.log('Generation successful.');

    let resultText = response.text;
    resultText = resultText.replace(/^\`\`\`(json)?/m, '').replace(/\`\`\`$/m, '').trim();

    const parsedQuestions = JSON.parse(resultText);
    res.json(parsedQuestions);

  } catch (err) {
    console.error('Error parsing PDF with Gemini:', err);
    res.status(500).json({ error: 'Error parsing PDF with Gemini: ' + err.message });
  }
});

// Bulk Create questions (admin)
app.post('/api/questions/bulk', authenticate, requireAdmin, async (req, res) => {
  try {
    const questionsArr = req.body.questions;
    if (!Array.isArray(questionsArr)) return res.status(400).json({ error: 'Expected an array of questions' });

    let insertedCount = 0;
    for (const q of questionsArr) {
      const { options: optData, numeric_answer, ...qData } = q;
      const { data: question, error: qErr } = await supabase.from('questions').insert(qData).select().single();
      if (qErr) continue;

      if (optData?.length && (qData.type === 'mcq' || qData.type === 'msq')) {
        const opts = optData.map((o, i) => ({ question_id: question.id, content: o.content, is_correct: o.is_correct, sort_order: i + 1 }));
        await supabase.from('options').insert(opts);
      }
      if (numeric_answer !== undefined && qData.type === 'numeric') {
        await supabase.from('numeric_answers').insert({ question_id: question.id, ...numeric_answer });
      }
      insertedCount++;
    }
    res.json({ success: true, count: insertedCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Update question (admin)
app.put('/api/questions/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { options: optData, numeric_answer, ...qData } = req.body;
    const { data, error } = await supabase.from('questions').update(qData).eq('id', req.params.id).select().single();
    if (error) throw error;

    if (optData) {
      await supabase.from('options').delete().eq('question_id', req.params.id);
      if (optData.length) {
        const opts = optData.map((o, i) => ({ question_id: req.params.id, content: o.content, is_correct: o.is_correct, sort_order: i + 1 }));
        await supabase.from('options').insert(opts);
      }
    }
    if (numeric_answer !== undefined) {
      await supabase.from('numeric_answers').delete().eq('question_id', req.params.id);
      if (numeric_answer) await supabase.from('numeric_answers').insert({ question_id: req.params.id, ...numeric_answer });
    }
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Delete question (admin)
app.delete('/api/questions/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { error } = await supabase.from('questions').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SCHEDULE ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/schedules', authenticate, async (req, res) => {
  try {
    let query = supabase.from('exam_schedules').select('*, exams(title, exam_code)');
    if (req.user.role !== 'admin') {
      // Student: schedules where they're enrolled
      const { data: enrollments } = await supabase.from('enrollments').select('schedule_id').eq('student_id', req.user.id);
      const ids = (enrollments || []).map(e => e.schedule_id);
      if (!ids.length) return res.json([]);
      query = query.in('id', ids);
    }
    const { data, error } = await query.order('start_time', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/schedules/:id/enrollments', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('enrollments').select('*, users(name, email, roll_number)').eq('schedule_id', req.params.id);
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Allowed fields for schedules (whitelist)
const SCHEDULE_ALLOWED_FIELDS = ['exam_id', 'batch_name', 'start_time', 'end_time', 'max_attempts', 'is_active'];
function pickScheduleFields(body) {
  return SCHEDULE_ALLOWED_FIELDS.reduce((acc, k) => {
    if (k in body) acc[k] = body[k];
    return acc;
  }, {});
}

app.post('/api/schedules', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('exam_schedules').insert({ ...pickScheduleFields(req.body), created_by: req.user.id }).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/schedules/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('exam_schedules').update(pickScheduleFields(req.body)).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/schedules/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { error } = await supabase.from('exam_schedules').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Enroll students in bulk
app.post('/api/schedules/:id/enroll', authenticate, requireAdmin, async (req, res) => {
  try {
    const { student_ids } = req.body;
    const enrollments = student_ids.map(sid => ({ schedule_id: req.params.id, student_id: sid }));
    const { data, error } = await supabase.from('enrollments').upsert(enrollments, { onConflict: 'schedule_id,student_id' }).select();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// RESULT ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// Start exam (create in-progress result)
app.post('/api/results/start', authenticate, async (req, res) => {
  try {
    const { exam_id, schedule_id } = req.body;

    // Verify enrollment
    if (schedule_id) {
      const { data: enroll } = await supabase.from('enrollments')
        .select('id').eq('schedule_id', schedule_id).eq('student_id', req.user.id).single();
      if (!enroll) return res.status(403).json({ error: 'You are not enrolled in this exam schedule' });
    }

    // Check if already started/submitted
    const { data: existing } = await supabase.from('results')
      .select('id, status').eq('exam_id', exam_id).eq('student_id', req.user.id);

    const submitted = existing?.find(r => r.status === 'submitted' || r.status === 'graded' || r.status === 'pending_grading');
    if (submitted) return res.status(400).json({ error: 'You have already submitted this exam', result_id: submitted.id });

    const inProgress = existing?.find(r => r.status === 'in_progress');
    if (inProgress) return res.json({ result_id: inProgress.id, resumed: true });

    const { data: exam } = await supabase.from('exams').select('total_marks').eq('id', exam_id).single();
    const { data: result, error } = await supabase.from('results').insert({
      exam_id,
      schedule_id,
      student_id: req.user.id,
      student_name: req.user.name,
      roll_number: req.user.roll_number,
      total_marks: exam?.total_marks || 0,
      status: 'in_progress',
      ip_address: req.ip,
      browser_info: req.headers['user-agent']
    }).select().single();
    if (error) throw error;
    res.json({ result_id: result.id, resumed: false });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Auto-save answers
app.post('/api/results/:id/save', authenticate, async (req, res) => {
  try {
    const { answers } = req.body; // [{ question_id, section_id, selected_options, answer_text, status, is_marked_review, time_spent }]
    if (!answers?.length) return res.json({ success: true });

    // Verify ownership
    const { data: result } = await supabase.from('results').select('student_id').eq('id', req.params.id).single();
    if (!result || result.student_id !== req.user.id) return res.status(403).json({ error: 'Not authorized' });

    const upserts = answers.map(a => ({
      result_id: req.params.id,
      question_id: a.question_id,
      section_id: a.section_id,
      selected_options: a.selected_options || [],
      answer_text: a.answer_text || null,
      status: a.status || 'not_answered',
      is_marked_review: a.is_marked_review || false,
      time_spent: a.time_spent || 0
    }));

    const { error } = await supabase.from('result_answers').upsert(upserts, { onConflict: 'result_id,question_id' });
    if (error) throw error;
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Submit exam
app.post('/api/results/:id/submit', authenticate, async (req, res) => {
  try {
    const { time_taken, answers } = req.body;
    const resultId = req.params.id;

    // Verify ownership
    const { data: result } = await supabase.from('results').select('*, exams(*)').eq('id', resultId).single();
    if (!result || result.student_id !== req.user.id) return res.status(403).json({ error: 'Not authorized' });
    if (result.status !== 'in_progress') return res.status(400).json({ error: 'Exam already submitted' });

    // Save final answers
    if (answers?.length) {
      const upserts = answers.map(a => ({
        result_id: resultId,
        question_id: a.question_id,
        section_id: a.section_id,
        selected_options: a.selected_options || [],
        answer_text: a.answer_text || null,
        status: a.status || 'not_answered',
        is_marked_review: a.is_marked_review || false,
        time_spent: a.time_spent || 0
      }));
      await supabase.from('result_answers').upsert(upserts, { onConflict: 'result_id,question_id' });
    }

    // Auto-grade MCQ / MSQ / Numeric
    const { data: resultAnswers } = await supabase.from('result_answers').select('*').eq('result_id', resultId);
    const { data: questions } = await supabase.from('questions').select('*, options(*), numeric_answers(*), exam_sections(*)').eq('exam_id', result.exam_id);
    const { data: sections } = await supabase.from('exam_sections').select('*').eq('exam_id', result.exam_id);

    let totalScore = 0;
    const sectionScores = {};

    // Init section scores
    (sections || []).forEach(s => {
      sectionScores[s.id] = { section_id: s.id, section_name: s.name, score: 0, max_score: 0, attempted: 0, correct: 0, wrong: 0, skipped: 0 };
    });

    // Grade each answer
    const gradedUpdates = [];
    for (const qa of (resultAnswers || [])) {
      const q = questions?.find(x => x.id === qa.question_id);
      if (!q) continue;

      const sectionId = q.section_id;
      const sc = sectionId ? (sectionScores[sectionId] || { section_id: sectionId, section_name: 'Unknown', score: 0, max_score: 0, attempted: 0, correct: 0, wrong: 0, skipped: 0 }) : null;
      if (sc) { sc.max_score += parseFloat(q.marks); sectionScores[sectionId] = sc; }

      let isCorrect = null;
      let marksAwarded = 0;

      if (qa.status === 'not_visited' || qa.status === 'not_answered') {
        if (sc) sc.skipped++;
      } else if (q.type === 'mcq') {
        const correctOpt = q.options?.find(o => o.is_correct);
        isCorrect = qa.selected_options?.length === 1 && qa.selected_options[0] === correctOpt?.id;
        marksAwarded = isCorrect ? parseFloat(q.marks) : -parseFloat(q.negative_marks || 0);
        if (sc) { sc.attempted++; isCorrect ? sc.correct++ : sc.wrong++; }
      } else if (q.type === 'msq') {
        const correctIds = (q.options?.filter(o => o.is_correct) || []).map(o => o.id).sort();
        const selectedIds = (qa.selected_options || []).sort();
        isCorrect = JSON.stringify(correctIds) === JSON.stringify(selectedIds);
        marksAwarded = isCorrect ? parseFloat(q.marks) : -parseFloat(q.negative_marks || 0);
        if (sc) { sc.attempted++; isCorrect ? sc.correct++ : sc.wrong++; }
      } else if (q.type === 'numeric') {
        const na = q.numeric_answers?.[0];
        if (na && qa.answer_text !== null && qa.answer_text !== '') {
          const val = parseFloat(qa.answer_text);
          isCorrect = Math.abs(val - parseFloat(na.correct_value)) <= parseFloat(na.tolerance || 0);
          marksAwarded = isCorrect ? parseFloat(q.marks) : -parseFloat(q.negative_marks || 0);
          if (sc) { sc.attempted++; isCorrect ? sc.correct++ : sc.wrong++; }
        }
      }
      // subjective — leave for admin grading

      totalScore += marksAwarded;
      if (sc) { sc.score += marksAwarded; sectionScores[sectionId] = sc; }

      gradedUpdates.push({ id: qa.id, is_correct: isCorrect, marks_awarded: marksAwarded });
    }

    // Update answer records with grades — single batch upsert instead of N sequential calls
    if (gradedUpdates.length) {
      await supabase.from('result_answers').upsert(
        gradedUpdates.map(u => ({ id: u.id, is_correct: u.is_correct, marks_awarded: u.marks_awarded })),
        { onConflict: 'id' }
      );
    }

    // Insert section scores
    const sectionRows = Object.values(sectionScores).map(s => ({ ...s, result_id: resultId }));
    if (sectionRows.length) await supabase.from('result_sections').upsert(sectionRows, { onConflict: 'result_id,section_id' });

    // Has subjective questions pending admin grading?
    const hasPending = questions?.some(q => q.type === 'subjective');

    const percentage = result.exams?.total_marks > 0 ? (totalScore / result.exams.total_marks) * 100 : 0;
    const passed = percentage >= (result.exams?.pass_percentage || 40);

    const { data: finalResult, error: updateErr } = await supabase.from('results').update({
      status: hasPending ? 'pending_grading' : 'submitted',
      total_score: Math.max(0, totalScore),
      percentage: Math.max(0, percentage),
      passed: hasPending ? false : passed,
      time_taken,
      submitted_at: new Date().toISOString()
    }).eq('id', resultId).select().single();
    if (updateErr) throw updateErr;

    res.json(finalResult);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get my results
app.get('/api/results/mine', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase.from('results')
      .select('*, exams(title, exam_code), result_sections(*)')
      .eq('student_id', req.user.id)
      .order('started_at', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get single result
app.get('/api/results/:id', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase.from('results')
      .select('*, exams(*), result_sections(*), result_answers(*, questions(content, type, marks, negative_marks, options(*), numeric_answers(*)))')
      .eq('id', req.params.id)
      .single();
    if (error || !data) return res.status(404).json({ error: 'Result not found' });
    if (req.user.role !== 'admin' && data.student_id !== req.user.id) return res.status(403).json({ error: 'Access denied' });
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get all results (admin)
app.get('/api/results', authenticate, requireAdmin, async (req, res) => {
  try {
    let query = supabase.from('results').select('*, exams(title, exam_code), result_sections(*)');
    if (req.query.examId) query = query.eq('exam_id', req.query.examId);
    const { data, error } = await query.order('submitted_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Leaderboard
app.get('/api/results/leaderboard/:examId', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase.from('results')
      .select('student_name, roll_number, total_score, total_marks, percentage, passed, time_taken, submitted_at')
      .eq('exam_id', req.params.examId)
      .in('status', ['submitted', 'graded'])
      .order('total_score', { ascending: false })
      .order('time_taken', { ascending: true });
    if (error) throw error;
    res.json((data || []).map((r, i) => ({ ...r, rank: i + 1 })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Grade subjective (admin)
app.put('/api/results/:id/grade', authenticate, requireAdmin, async (req, res) => {
  try {
    const { grades } = req.body; // { answer_id: { marks, feedback } }
    let bonusScore = 0;
    for (const [answerId, grade] of Object.entries(grades)) {
      await supabase.from('result_answers').update({
        marks_awarded: grade.marks,
        admin_feedback: grade.feedback,
        is_correct: grade.marks > 0,
        graded_by: req.user.id
      }).eq('id', answerId);
      bonusScore += grade.marks;
    }

    // Recalculate total
    const { data: allAnswers } = await supabase.from('result_answers').select('marks_awarded').eq('result_id', req.params.id);
    const newTotal = (allAnswers || []).reduce((s, a) => s + (a.marks_awarded || 0), 0);

    const { data: result } = await supabase.from('results').select('total_marks, exams(pass_percentage)').eq('id', req.params.id).single();
    const percentage = result?.total_marks > 0 ? (Math.max(0, newTotal) / result.total_marks) * 100 : 0;

    const { data: updated } = await supabase.from('results').update({
      total_score: Math.max(0, newTotal),
      percentage: Math.max(0, percentage),
      passed: percentage >= (result?.exams?.pass_percentage || 40),
      status: 'graded',
      graded_at: new Date().toISOString()
    }).eq('id', req.params.id).select().single();

    res.json(updated);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Export results as CSV (admin)
app.get('/api/results/export/:examId', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('results')
      .select('student_name, roll_number, total_score, total_marks, percentage, passed, time_taken, submitted_at, status, result_sections(*)')
      .eq('exam_id', req.params.examId)
      .order('total_score', { ascending: false });
    if (error) throw error;

    let csv = 'Rank,Name,Roll Number,Score,Total Marks,Percentage,Status,Time Taken (s),Submitted At\n';
    (data || []).forEach((r, i) => {
      csv += `${i + 1},"${r.student_name || ''}","${r.roll_number || ''}",${r.total_score},${r.total_marks},${r.percentage?.toFixed(2)}%,${r.passed ? 'PASS' : 'FAIL'},${r.time_taken},"${r.submitted_at || ''}"\n`;
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="results_${req.params.examId}.csv"`);
    res.send(csv);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Proctoring log
app.post('/api/proctor/log', authenticate, async (req, res) => {
  try {
    const { result_id, event_type, details } = req.body;

    // Verify ownership
    const { data: result } = await supabase.from('results').select('student_id').eq('id', result_id).single();
    if (!result || result.student_id !== req.user.id) return res.status(403).json({ error: 'Not authorized' });

    // Increment counters on result row
    if (event_type === 'tab_switch') {
      const { data: r } = await supabase.from('results').select('tab_switches').eq('id', result_id).single();
      await supabase.from('results').update({ tab_switches: (r?.tab_switches || 0) + 1 }).eq('id', result_id);
    }
    if (event_type === 'fullscreen_exit') {
      const { data: r } = await supabase.from('results').select('fullscreen_exits').eq('id', result_id).single();
      await supabase.from('results').update({ fullscreen_exits: (r?.fullscreen_exits || 0) + 1 }).eq('id', result_id);
    }

    await supabase.from('proctoring_logs').insert({ result_id, event_type, details });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get proctoring logs for admin
app.get('/api/proctor/logs/:resultId', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('proctoring_logs')
      .select('*')
      .eq('result_id', req.params.resultId)
      .order('timestamp', { ascending: true });
    if (error) throw error;
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Stats (admin)
app.get('/api/stats', authenticate, requireAdmin, async (req, res) => {
  try {
    const [{ count: students }, { count: exams }, { count: submissions }, { count: activeSessions }] = await Promise.all([
      supabase.from('users').select('*', { count: 'exact', head: true }).eq('role', 'student'),
      supabase.from('exams').select('*', { count: 'exact', head: true }),
      supabase.from('results').select('*', { count: 'exact', head: true }).in('status', ['submitted', 'graded']),
      supabase.from('results').select('*', { count: 'exact', head: true }).eq('status', 'in_progress')
    ]);
    res.json({ totalStudents: students || 0, totalExams: exams || 0, totalSubmissions: submissions || 0, activeExams: activeSessions || 0 });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Users list (admin)
app.get('/api/users', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select('id, name, email, roll_number, role, is_active, created_at').eq('role', 'student').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});


// ═══════════════════════════════════════════════════════════════════════════════
// CODING EXAMS ROUTES — Production
// ═══════════════════════════════════════════════════════════════════════════════

// Rate limiter for code execution (10 per minute)
const codeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many code executions. Please wait a moment.' }
});
app.use('/api/coding/execute', codeLimiter);
app.use('/api/coding/submit', codeLimiter);

// Piston language map
const PISTON_LANGS = {
  'python':     { language: 'python',     version: '3.10.0' },
  'javascript': { language: 'javascript', version: '18.15.0' },
  'java':       { language: 'java',       version: '15.0.2' },
  'cpp':        { language: 'c++',        version: '10.2.0' },
  'c':          { language: 'c',          version: '10.2.0' }
};

const MAX_CODE_SIZE = 50 * 1024; // 50KB

// Helper: execute code via Piston
async function executeCode(code, language, stdin, timeLimitMs = 10000) {
  const langInfo = PISTON_LANGS[language] || PISTON_LANGS['python'];
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), Math.min(timeLimitMs + 5000, 30000));

  try {
    const response = await fetch('https://emkc.org/api/v2/piston/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        language: langInfo.language,
        version: langInfo.version,
        files: [{ content: code }],
        stdin: stdin || '',
        run_timeout: timeLimitMs
      })
    });
    const result = await response.json();
    return {
      stdout: result.run?.stdout || '',
      stderr: result.run?.stderr || '',
      compile_output: result.compile?.stderr || '',
      exit_code: result.run?.code ?? -1,
      signal: result.run?.signal || null
    };
  } catch (err) {
    if (err.name === 'AbortError') {
      return { stdout: '', stderr: 'Execution timed out', compile_output: '', exit_code: -1, signal: 'SIGKILL' };
    }
    throw err;
  } finally {
    clearTimeout(timeout);
  }
}

// Helper: normalize output for comparison (trim trailing whitespace per line, trailing newlines)
function normalizeOutput(str) {
  return (str || '').split('\n').map(l => l.trimEnd()).join('\n').replace(/\n+$/, '');
}

// ── ADMIN: List coding questions ──────────────────────────────────────────────
app.get('/api/admin/coding-questions', authenticate, requireAdmin, async (req, res) => {
  try {
    let query = supabase.from('coding_questions').select('*, test_cases(id)');

    if (req.query.difficulty) query = query.eq('difficulty', req.query.difficulty);
    if (req.query.search) query = query.ilike('title', `%${req.query.search}%`);
    if (req.query.active === 'true') query = query.eq('is_active', true);
    if (req.query.active === 'false') query = query.eq('is_active', false);

    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) throw error;

    // Add test_case_count
    const result = (data || []).map(q => ({
      ...q,
      test_case_count: q.test_cases?.length || 0,
      test_cases: undefined
    }));

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ADMIN: Get single coding question with test cases ─────────────────────────
app.get('/api/admin/coding-questions/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('coding_questions')
      .select('*, test_cases(*)')
      .eq('id', req.params.id)
      .single();
    if (error || !data) return res.status(404).json({ error: 'Question not found' });

    // Sort test cases
    if (data.test_cases) data.test_cases.sort((a, b) => a.sort_order - b.sort_order);

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ADMIN: Create coding question ─────────────────────────────────────────────
app.post('/api/admin/coding-questions', authenticate, requireAdmin, async (req, res) => {
  try {
    const { test_cases: testCases, ...qData } = req.body;

    // Whitelist fields
    const allowed = ['title', 'description', 'constraints', 'difficulty', 'tags', 'examples',
                     'hints', 'editorial', 'time_limit_ms', 'memory_limit_kb', 'skeleton_code', 'is_active'];
    const cleanQ = allowed.reduce((acc, k) => { if (k in qData) acc[k] = qData[k]; return acc; }, {});
    cleanQ.created_by = req.user.id;

    const { data: question, error: qErr } = await supabase
      .from('coding_questions').insert(cleanQ).select().single();
    if (qErr) throw qErr;

    // Insert test cases if provided
    if (Array.isArray(testCases) && testCases.length > 0) {
      const tcRows = testCases.map((tc, i) => ({
        question_id: question.id,
        label: tc.label || `Test Case ${i + 1}`,
        input: tc.input || '',
        expected_output: tc.expected_output || '',
        explanation: tc.explanation || null,
        is_hidden: tc.is_hidden !== undefined ? tc.is_hidden : (i >= 2), // first 2 visible by default
        weight: tc.weight || 10,
        sort_order: tc.sort_order || (i + 1)
      }));
      await supabase.from('test_cases').insert(tcRows);
    }

    // Return full question with test cases
    const { data: full } = await supabase
      .from('coding_questions').select('*, test_cases(*)').eq('id', question.id).single();
    res.json(full);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ADMIN: Update coding question ─────────────────────────────────────────────
app.put('/api/admin/coding-questions/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { test_cases: testCases, ...qData } = req.body;

    const allowed = ['title', 'description', 'constraints', 'difficulty', 'tags', 'examples',
                     'hints', 'editorial', 'time_limit_ms', 'memory_limit_kb', 'skeleton_code', 'is_active'];
    const cleanQ = allowed.reduce((acc, k) => { if (k in qData) acc[k] = qData[k]; return acc; }, {});

    const { data, error } = await supabase
      .from('coding_questions').update(cleanQ).eq('id', req.params.id).select().single();
    if (error) throw error;

    // Replace test cases if provided
    if (Array.isArray(testCases)) {
      await supabase.from('test_cases').delete().eq('question_id', req.params.id);
      if (testCases.length > 0) {
        const tcRows = testCases.map((tc, i) => ({
          question_id: req.params.id,
          label: tc.label || `Test Case ${i + 1}`,
          input: tc.input || '',
          expected_output: tc.expected_output || '',
          explanation: tc.explanation || null,
          is_hidden: tc.is_hidden !== undefined ? tc.is_hidden : true,
          weight: tc.weight || 10,
          sort_order: tc.sort_order || (i + 1)
        }));
        await supabase.from('test_cases').insert(tcRows);
      }
    }

    const { data: full } = await supabase
      .from('coding_questions').select('*, test_cases(*)').eq('id', req.params.id).single();
    res.json(full);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ADMIN: Delete coding question ─────────────────────────────────────────────
app.delete('/api/admin/coding-questions/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { error } = await supabase.from('coding_questions').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ADMIN: Add test case to a question ────────────────────────────────────────
app.post('/api/admin/coding-questions/:id/test-cases', authenticate, requireAdmin, async (req, res) => {
  try {
    const { label, input, expected_output, explanation, is_hidden, weight, sort_order } = req.body;
    const { data, error } = await supabase.from('test_cases').insert({
      question_id: req.params.id,
      label: label || 'Test Case',
      input: input || '',
      expected_output: expected_output || '',
      explanation: explanation || null,
      is_hidden: is_hidden !== undefined ? is_hidden : true,
      weight: weight || 10,
      sort_order: sort_order || 1
    }).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ADMIN: Update test case ───────────────────────────────────────────────────
app.put('/api/admin/test-cases/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const allowed = ['label', 'input', 'expected_output', 'explanation', 'is_hidden', 'weight', 'sort_order'];
    const cleanTC = allowed.reduce((acc, k) => { if (k in req.body) acc[k] = req.body[k]; return acc; }, {});
    const { data, error } = await supabase.from('test_cases').update(cleanTC).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ADMIN: Delete test case ───────────────────────────────────────────────────
app.delete('/api/admin/test-cases/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { error } = await supabase.from('test_cases').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ADMIN: Get all coding submissions (optionally filtered) ───────────────────
app.get('/api/admin/coding-submissions', authenticate, requireAdmin, async (req, res) => {
  try {
    let query = supabase.from('coding_submissions')
      .select('*, coding_questions(title), users(name, email, roll_number)');
    if (req.query.questionId) query = query.eq('question_id', req.query.questionId);
    if (req.query.studentId) query = query.eq('student_id', req.query.studentId);
    const { data, error } = await query.order('submitted_at', { ascending: false }).limit(200);
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// STUDENT CODING ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// ── STUDENT: List coding questions ────────────────────────────────────────────
app.get('/api/coding-questions', authenticate, async (req, res) => {
  try {
    let query = supabase.from('coding_questions')
      .select('id, title, difficulty, tags, time_limit_ms, memory_limit_kb, created_at')
      .eq('is_active', true);

    if (req.query.difficulty) query = query.eq('difficulty', req.query.difficulty);
    if (req.query.search) query = query.ilike('title', `%${req.query.search}%`);

    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) throw error;

    // Attach best submission status per question for this student
    const qIds = (data || []).map(q => q.id);
    let bestSubmissions = {};
    if (qIds.length > 0) {
      const { data: subs } = await supabase
        .from('coding_submissions')
        .select('question_id, status, score, total_score')
        .eq('student_id', req.user.id)
        .in('question_id', qIds)
        .order('score', { ascending: false });
      for (const s of (subs || [])) {
        if (!bestSubmissions[s.question_id] || s.score > bestSubmissions[s.question_id].score) {
          bestSubmissions[s.question_id] = s;
        }
      }
    }

    const result = (data || []).map(q => ({
      ...q,
      best_submission: bestSubmissions[q.id] || null
    }));

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── STUDENT: Get single coding question ───────────────────────────────────────
app.get('/api/coding-questions/:id', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('coding_questions')
      .select('id, title, description, constraints, difficulty, tags, examples, hints, time_limit_ms, memory_limit_kb, skeleton_code')
      .eq('id', req.params.id)
      .eq('is_active', true)
      .single();
    if (error || !data) return res.status(404).json({ error: 'Question not found' });

    // Get visible test cases only
    const { data: visibleTests } = await supabase
      .from('test_cases')
      .select('id, label, input, expected_output, explanation, sort_order')
      .eq('question_id', req.params.id)
      .eq('is_hidden', false)
      .order('sort_order');

    data.visible_test_cases = visibleTests || [];

    // Get student's best submission for this question
    const { data: bestSub } = await supabase
      .from('coding_submissions')
      .select('id, status, score, total_score, passed_tests, total_tests, language, submitted_at')
      .eq('question_id', req.params.id)
      .eq('student_id', req.user.id)
      .order('score', { ascending: false })
      .limit(1)
      .maybeSingle();

    data.best_submission = bestSub || null;

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── STUDENT: Run code (against custom/sample input) ───────────────────────────
app.post('/api/coding/execute', authenticate, async (req, res) => {
  try {
    const { code, language, input, question_id } = req.body;

    if (!code || !language) return res.status(400).json({ error: 'Code and language are required' });
    if (Buffer.byteLength(code, 'utf8') > MAX_CODE_SIZE) {
      return res.status(400).json({ error: `Code exceeds maximum size of ${MAX_CODE_SIZE / 1024}KB` });
    }
    if (!PISTON_LANGS[language]) {
      return res.status(400).json({ error: `Unsupported language: ${language}. Supported: ${Object.keys(PISTON_LANGS).join(', ')}` });
    }

    // Get time limit from question if provided
    let timeLimitMs = 10000;
    if (question_id) {
      const { data: q } = await supabase.from('coding_questions').select('time_limit_ms').eq('id', question_id).single();
      if (q) timeLimitMs = q.time_limit_ms || 10000;
    }

    const result = await executeCode(code, language, input, timeLimitMs);

    // Determine status
    let status = 'Success';
    if (result.compile_output) status = 'Compilation Error';
    else if (result.signal === 'SIGKILL') status = 'Time Limit Exceeded';
    else if (result.exit_code !== 0) status = 'Runtime Error';

    res.json({
      output: result.stdout,
      error: result.stderr || result.compile_output,
      status,
      exit_code: result.exit_code
    });
  } catch (err) {
    res.status(500).json({ error: 'Code execution failed', details: err.message });
  }
});

// ── STUDENT: Submit code (run against all test cases, grade) ──────────────────
app.post('/api/coding/submit', authenticate, async (req, res) => {
  try {
    const { code, language, question_id, exam_id } = req.body;

    if (!code || !language || !question_id) {
      return res.status(400).json({ error: 'code, language, and question_id are required' });
    }
    if (Buffer.byteLength(code, 'utf8') > MAX_CODE_SIZE) {
      return res.status(400).json({ error: `Code exceeds maximum size of ${MAX_CODE_SIZE / 1024}KB` });
    }
    if (!PISTON_LANGS[language]) {
      return res.status(400).json({ error: `Unsupported language: ${language}` });
    }

    // Get question + all test cases
    const { data: question } = await supabase
      .from('coding_questions').select('*').eq('id', question_id).single();
    if (!question) return res.status(404).json({ error: 'Question not found' });

    const { data: allTests } = await supabase
      .from('test_cases')
      .select('*')
      .eq('question_id', question_id)
      .order('sort_order');

    if (!allTests || allTests.length === 0) {
      return res.status(400).json({ error: 'No test cases configured for this question' });
    }

    const timeLimitMs = question.time_limit_ms || 2000;
    const testResults = [];
    let totalScore = 0;
    let totalPossible = 0;
    let passedTests = 0;
    let worstTime = 0;
    let overallStatus = 'Accepted';
    let compileError = null;
    let runtimeError = null;

    // Run against each test case
    for (const tc of allTests) {
      totalPossible += tc.weight;
      const startTime = Date.now();
      const result = await executeCode(code, language, tc.input, timeLimitMs);
      const execTime = Date.now() - startTime;

      let tcStatus = 'Accepted';
      let passed = false;

      if (result.compile_output) {
        tcStatus = 'Compilation Error';
        compileError = result.compile_output;
        overallStatus = 'Compilation Error';
      } else if (result.signal === 'SIGKILL') {
        tcStatus = 'Time Limit Exceeded';
        if (overallStatus === 'Accepted') overallStatus = 'Time Limit Exceeded';
      } else if (result.exit_code !== 0) {
        tcStatus = 'Runtime Error';
        runtimeError = result.stderr;
        if (overallStatus === 'Accepted') overallStatus = 'Runtime Error';
      } else {
        // Compare output
        const actual = normalizeOutput(result.stdout);
        const expected = normalizeOutput(tc.expected_output);
        if (actual === expected) {
          passed = true;
          passedTests++;
          totalScore += tc.weight;
        } else {
          tcStatus = 'Wrong Answer';
          if (overallStatus === 'Accepted') overallStatus = 'Wrong Answer';
        }
      }

      if (execTime > worstTime) worstTime = execTime;

      testResults.push({
        test_id: tc.id,
        label: tc.label,
        is_hidden: tc.is_hidden,
        passed,
        time_ms: execTime,
        status: tcStatus,
        // Only show output/expected for visible tests
        output: tc.is_hidden ? undefined : normalizeOutput(result.stdout),
        expected: tc.is_hidden ? undefined : normalizeOutput(tc.expected_output)
      });

      // Stop on compilation error (all tests will fail)
      if (tcStatus === 'Compilation Error') {
        // Mark remaining tests as CE
        for (let i = allTests.indexOf(tc) + 1; i < allTests.length; i++) {
          totalPossible += allTests[i].weight;
          testResults.push({
            test_id: allTests[i].id,
            label: allTests[i].label,
            is_hidden: allTests[i].is_hidden,
            passed: false,
            time_ms: 0,
            status: 'Compilation Error'
          });
        }
        break;
      }
    }

    // Determine final status
    if (passedTests === allTests.length) overallStatus = 'Accepted';
    else if (passedTests > 0 && overallStatus === 'Wrong Answer') overallStatus = 'Partial';

    // Store submission
    const { data: submission, error: subErr } = await supabase.from('coding_submissions').insert({
      question_id,
      student_id: req.user.id,
      exam_id: exam_id || null,
      language,
      code,
      status: overallStatus,
      score: totalScore,
      total_score: totalPossible,
      passed_tests: passedTests,
      total_tests: allTests.length,
      execution_time_ms: worstTime,
      test_results: testResults,
      compile_error: compileError,
      runtime_error: runtimeError
    }).select().single();

    if (subErr) throw subErr;

    res.json(submission);
  } catch (err) {
    res.status(500).json({ error: 'Submission failed', details: err.message });
  }
});

// ── STUDENT: Get my submissions ───────────────────────────────────────────────
app.get('/api/coding/submissions', authenticate, async (req, res) => {
  try {
    let query = supabase.from('coding_submissions')
      .select('id, question_id, language, status, score, total_score, passed_tests, total_tests, execution_time_ms, submitted_at, coding_questions(title)')
      .eq('student_id', req.user.id);

    if (req.query.questionId) query = query.eq('question_id', req.query.questionId);

    const { data, error } = await query.order('submitted_at', { ascending: false }).limit(50);
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── STUDENT: Get single submission detail ─────────────────────────────────────
app.get('/api/coding/submissions/:id', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('coding_submissions')
      .select('*, coding_questions(title, difficulty)')
      .eq('id', req.params.id)
      .single();
    if (error || !data) return res.status(404).json({ error: 'Submission not found' });
    if (data.student_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── 404 Catch-All ──────────────────────────────────────────────────────────────
// Serve a custom 404 page for any unmatched routes
app.use((req, res) => {
  if (req.accepts('html')) {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
  } else {
    res.status(404).json({ error: 'Not found' });
  }
});

// ── Start Server ───────────────────────────────────────────────────────────────
// Skip listen() when running as a serverless function (Netlify/Vercel)
const isServerless = process.env.VERCEL || process.env.NETLIFY || process.env.LAMBDA_TASK_ROOT;
if (!isServerless) {
  app.listen(PORT, () => {
    console.log(`\n🚀 ExamHub v2 running at http://localhost:${PORT}`);
    console.log(`   Supabase: ${supabaseUrl}`);
    console.log(`   Admin: Update user role to 'admin' in Supabase dashboard\n`);
  });
}

module.exports = app;
