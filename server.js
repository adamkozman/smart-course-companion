// ============================== 
// PROJECT CONTRIBUTIONS 
// ============================== 
// Adam -> Courses & Assessments (creation, management) 
// Reza -> Authentication (Login, Signup, Password reset, Email verification) 
// Hanad -> Grades system (teacher + student) + Calendar + Grade data initialization fix 
// ==============================
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require("fs");
const db = require('./db');
const nodemailer = require("nodemailer");

const mailConfigured = Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
const transporter = mailConfigured ? nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: process.env.SMTP_SECURE === 'true',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
}) : null;

const app = express();
const PORT = Number(process.env.PORT || 3000);

const resetFile = path.join(__dirname, "reset-codes.json");

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Serve only frontend assets; never expose server code or local account data.
app.use((req, res, next) => {
  const pathname = req.path;
  if (/^\/[^/]+\.html$/.test(pathname) || /^\/(Styles|Icons|public)\//.test(pathname)) {
    return express.static(__dirname, { dotfiles: 'deny' })(req, res, next);
  }
  next();
});

app.use(session({
  secret: process.env.SESSION_SECRET || require('crypto').randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Auth middleware
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

function requireStudent(req, res, next) {
  if (!req.session.userId || req.session.role !== 'student') {
    return res.status(403).json({ error: 'Student access required' });
  }
  next();
}

function requireTeacher(req, res, next) {
  if (!req.session.userId || req.session.role !== 'teacher') {
    return res.status(403).json({ error: 'Teacher access required' });
  }
  next();
}

function cleanText(value) {
  if (value === undefined || value === null) {
    return '';
  }
  return String(value).trim();
}

function getProfileFields(body, role) {
  const name = cleanText(body.name);
  const email = cleanText(body.email);
  const phone = cleanText(body.phone);
  const program = role === 'student' ? cleanText(body.program) : '';
  const phd = role === 'teacher' ? cleanText(body.phd) : '';
  const studentNumber = role === 'student' ? cleanText(body.student_number || body.studentId) : '';
  const teacherNumber = role === 'teacher' ? cleanText(body.teacher_number || body.teacherId) : '';

  return {
    name,
    email,
    phone,
    program,
    phd,
    studentNumber,
    teacherNumber
  };
}

// Reset code helper functions
function readResetCodes() {
  try {
    const text = fs.readFileSync(resetFile, "utf8");
    return JSON.parse(text);
  } catch (error) {
    return [];
  }
}

function saveResetCodes(codes) {
  fs.writeFileSync(resetFile, JSON.stringify(codes, null, 2));
}

function makeCode() {
  const number = Math.floor(100000 + Math.random() * 900000);
  return number.toString();
}

// ─────────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────────

// Student login
app.post('/api/auth/student/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  db.get('SELECT * FROM users WHERE email = ? AND role = ?', [email, 'student'], (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    bcrypt.compare(password, user.password_hash, (err, match) => {
      if (err || !match) return res.status(401).json({ error: 'Invalid credentials' });
      req.session.userId = user.id;
      req.session.role = 'student';
      req.session.name = user.name;
      res.json({ success: true, name: user.name });
    });
  });
});

// Teacher login
app.post('/api/auth/teacher/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  db.get('SELECT * FROM users WHERE email = ? AND role = ?', [email, 'teacher'], (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    bcrypt.compare(password, user.password_hash, (err, match) => {
      if (err || !match) return res.status(401).json({ error: 'Invalid credentials' });
      req.session.userId = user.id;
      req.session.role = 'teacher';
      req.session.name = user.name;
      res.json({ success: true, name: user.name });
    });
  });
});

// Student sign up
app.post('/api/auth/student/register', (req, res) => {
  const { name, email, password, student_number } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });

  db.get('SELECT id FROM users WHERE email = ?', [email], (err, existing) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    bcrypt.hash(password, 10, (err, hash) => {
      if (err) return res.status(500).json({ error: 'Server error' });
      db.run(
        'INSERT INTO users (name, email, password_hash, role, student_number) VALUES (?, ?, ?, ?, ?)',
        [name, email, hash, 'student', cleanText(student_number)],
        function(err) {
          if (err) return res.status(500).json({ error: 'Database error' });
          req.session.userId = this.lastID;
          req.session.role = 'student';
          req.session.name = name;
          res.json({ success: true, name });
        }
      );
    });
  });
});

// Teacher sign up
app.post('/api/auth/teacher/register', (req, res) => {
  const { name, email, password, teacher_number } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });

  db.get('SELECT id FROM users WHERE email = ?', [email], (err, existing) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    bcrypt.hash(password, 10, (err, hash) => {
      if (err) return res.status(500).json({ error: 'Server error' });
      db.run(
        'INSERT INTO users (name, email, password_hash, role, teacher_number) VALUES (?, ?, ?, ?, ?)',
        [name, email, hash, 'teacher', cleanText(teacher_number)],
        function(err) {
          if (err) return res.status(500).json({ error: 'Database error' });
          req.session.userId = this.lastID;
          req.session.role = 'teacher';
          req.session.name = name;
          res.json({ success: true, name });
        }
      );
    });
  });
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// Get current session info
app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  res.json({
    loggedIn: true,
    role: req.session.role,
    name: req.session.name,
    userId: req.session.userId
  });
});

app.get('/', (req, res) => {
  res.redirect('/Login_Front_Page.html');
});

app.get('/api/account/profile', requireAuth, (req, res) => {
  db.get(
    `SELECT id, name, email, role, student_number, teacher_number, phone, program, phd
     FROM users
     WHERE id = ?`,
    [req.session.userId],
    (err, user) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!user) return res.status(404).json({ error: 'User not found' });

      res.json({
        id: user.id,
        name: user.name || '',
        email: user.email || '',
        role: user.role,
        student_number: user.student_number || '',
        teacher_number: user.teacher_number || '',
        phone: user.phone || '',
        program: user.program || '',
        phd: user.phd || ''
      });
    }
  );
});

app.put('/api/account/profile', requireAuth, (req, res) => {
  const role = req.session.role;
  const profile = getProfileFields(req.body, role);

  if (!profile.name || !profile.email) {
    return res.status(400).json({ error: 'Name and email are required' });
  }

  if (role === 'student' && !profile.studentNumber) {
    return res.status(400).json({ error: 'Student ID is required' });
  }

  if (role === 'teacher' && !profile.teacherNumber) {
    return res.status(400).json({ error: 'Teacher ID is required' });
  }

  db.get(
    'SELECT id FROM users WHERE email = ? AND id != ?',
    [profile.email, req.session.userId],
    (err, existingUser) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (existingUser) return res.status(409).json({ error: 'Email already registered' });

      db.run(
        `UPDATE users
         SET name = ?, email = ?, student_number = ?, teacher_number = ?, phone = ?, program = ?, phd = ?
         WHERE id = ?`,
        [
          profile.name,
          profile.email,
          profile.studentNumber || null,
          profile.teacherNumber || null,
          profile.phone || null,
          profile.program || null,
          profile.phd || null,
          req.session.userId
        ],
        function(updateError) {
          if (updateError) return res.status(500).json({ error: 'Database error' });

          req.session.name = profile.name;

          if (role === 'teacher') {
            db.run(
              'UPDATE courses SET teacher_name = ? WHERE teacher_id = ?',
              [profile.name, req.session.userId],
              function(courseError) {
                if (courseError) return res.status(500).json({ error: 'Database error' });
                res.json({ success: true });
              }
            );
            return;
          }

          res.json({ success: true });
        }
      );
    }
  );
});

// --- Student Courses ---

// returns all courses the student is enrolled in, with stats for each
app.get('/api/student/courses', requireStudent, (req, res) => {
  const studentId = req.session.userId;
  db.all(`
    SELECT c.*, e.id as enrollment_id
    FROM courses c
    JOIN enrollments e ON e.course_id = c.id
    WHERE e.student_id = ?
    ORDER BY c.created_at DESC
  `, [studentId], (err, courses) => {
    if (err) return res.status(500).json({ error: 'Database error' });

    const promises = courses.map(course => new Promise((resolve) => {
      db.all(`
        SELECT a.*, sa.earned_marks, sa.status as student_status
        FROM assessments a
        LEFT JOIN student_assessments sa ON sa.assessment_id = a.id AND sa.student_id = ?
        WHERE a.course_id = ?
      `, [studentId, course.id], (err, assessments) => {
        if (err) {
          resolve({ ...course, assessments: [], stats: {} });
          return;
        }

        const total = assessments.length;
        const done = assessments.filter(a => a.student_status === 'Completed').length;
        const graded = assessments.filter(a => a.earned_marks !== null && a.total_marks);
        const avg = graded.length
          ? Math.round(graded.reduce((sum, a) => sum + (a.earned_marks / a.total_marks * 100), 0) / graded.length)
          : null;
        const upcoming = assessments
          .filter(a => a.student_status !== 'Completed' && a.due_date)
          .sort((a, b) => new Date(a.due_date) - new Date(b.due_date))
          .slice(0, 3);

        resolve({
          ...course,
          stats: { total, done, avg, progress: total ? Math.round(done / total * 100) : 0 },
          upcoming
        });
      });
    }));

    Promise.all(promises).then(result => res.json(result));
  });
});

// student joins a course using the course code, section and term
app.post('/api/student/courses/join', requireStudent, (req, res) => {
  const studentId = req.session.userId;
  const { course_code, section, term } = req.body;

  if (!course_code || !section || !term) {
    return res.status(400).json({ error: 'All fields required' });
  }

  db.get(
    'SELECT * FROM courses WHERE course_code = ? AND section = ? AND term = ?',
    [course_code.trim(), section.trim(), term.trim()],
    (err, course) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!course) return res.status(404).json({ error: 'Course not found' });

      db.get(
        'SELECT id FROM enrollments WHERE student_id = ? AND course_id = ?',
        [studentId, course.id],
        (err, existing) => {
          if (err) return res.status(500).json({ error: 'Database error' });
          if (existing) return res.status(409).json({ error: 'Already enrolled' });

          db.run(
            'INSERT INTO enrollments (student_id, course_id) VALUES (?, ?)',
            [studentId, course.id],
            function(err) {
              if (err) return res.status(500).json({ error: 'Database error' });

              
              db.all(
                'SELECT id FROM assessments WHERE course_id = ?',
                [course.id],
                (err, assessments) => {
                  if (!err && assessments.length) {
                    assessments.forEach(a => {
                      db.run(
                        'INSERT OR IGNORE INTO student_assessments (student_id, assessment_id) VALUES (?, ?)',
                        [studentId, a.id]
                      );
                    });
                  }

                
                  res.json({ success: true, course });
                }
              );
            }
          );
        }
      );
    }
  );
});

// student leaves/drops a course
app.delete('/api/student/courses/:courseId', requireStudent, (req, res) => {
  const studentId = req.session.userId;
  db.run(
    'DELETE FROM enrollments WHERE student_id = ? AND course_id = ?',
    [studentId, req.params.courseId],
    function(err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true });
    }
  );
});

// --- Student Assessments ---

// get all assessments for a specific course the student is in
app.get('/api/student/assessments/:courseId', requireStudent, (req, res) => {
  const studentId = req.session.userId;
  const courseId = req.params.courseId;

  db.all(`
    SELECT a.*, sa.earned_marks, sa.status as student_status
    FROM assessments a
    LEFT JOIN student_assessments sa ON sa.assessment_id = a.id AND sa.student_id = ?
    WHERE a.course_id = ?
    ORDER BY a.due_date ASC
  `, [studentId, courseId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

// student saves their earned marks and status for an assessment
app.put('/api/student/assessments/:assessmentId', requireStudent, (req, res) => {
  const studentId = req.session.userId;
  const assessmentId = req.params.assessmentId;
  const { earned_marks, status } = req.body;

  if (earned_marks !== undefined && earned_marks !== null && earned_marks !== '') {
    db.get('SELECT total_marks FROM assessments WHERE id = ?', [assessmentId], (err, a) => {
      if (err || !a) return res.status(400).json({ error: 'Assessment not found' });
      if (parseFloat(earned_marks) > a.total_marks) {
        return res.status(400).json({ error: `Earned marks cannot exceed total marks (${a.total_marks})` });
      }
      if (parseFloat(earned_marks) < 0) {
        return res.status(400).json({ error: 'Earned marks cannot be negative' });
      }
      upsert();
    });
  } else {
    upsert();
  }

  function upsert() {
    db.run(`
      INSERT INTO student_assessments (student_id, assessment_id, earned_marks, status)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(student_id, assessment_id) DO UPDATE SET
        earned_marks = excluded.earned_marks,
        status = excluded.status
    `, [studentId, assessmentId, earned_marks || null, status || 'Pending'], (err) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true });
    });
  }
});

// --- Teacher Courses ---

// get all courses this teacher created
app.get('/api/teacher/courses', requireTeacher, (req, res) => {
  db.all(
    'SELECT * FROM courses WHERE teacher_id = ? ORDER BY created_at DESC',
    [req.session.userId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    }
  );
});

// teacher creates a new course
app.post('/api/teacher/courses', requireTeacher, (req, res) => {
  const { course_code, course_name, section, term } = req.body;
  if (!course_code || !course_name || !section || !term) {
    return res.status(400).json({ error: 'All fields required' });
  }

  const teacherId = req.session.userId;

  db.get(
    'SELECT id FROM courses WHERE course_code = ? AND section = ? AND term = ? AND teacher_id = ?',
    [course_code.trim(), section.trim(), term.trim(), teacherId],
    (err, existing) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (existing) return res.status(409).json({ error: 'You already have this course/section/term' });

      db.get('SELECT name FROM users WHERE id = ?', [teacherId], (err, teacher) => {
        const teacherName = teacher ? teacher.name : 'Instructor';

        db.run(`
          INSERT INTO courses (course_code, course_name, section, term, teacher_id, teacher_name)
          VALUES (?, ?, ?, ?, ?, ?)
        `, [course_code.trim(), course_name.trim(), section.trim(), term.trim(), teacherId, teacherName], function(err) {
          if (err) return res.status(500).json({ error: 'Database error' });
          res.json({
            success: true,
            id: this.lastID,
            course_code,
            course_name,
            section,
            term,
            teacher_name: teacherName
          });
        });
      });
    }
  );
});

// teacher deletes one of their courses
app.delete('/api/teacher/courses/:courseId', requireTeacher, (req, res) => {
  db.run(
    'DELETE FROM courses WHERE id = ? AND teacher_id = ?',
    [req.params.courseId, req.session.userId],
    function(err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (this.changes === 0) return res.status(404).json({ error: 'Course not found' });
      res.json({ success: true });
    }
  );
});

// enable or disable a course
app.patch('/api/teacher/courses/:courseId/toggle', requireTeacher, (req, res) => {
  db.get(
    'SELECT active FROM courses WHERE id = ? AND teacher_id = ?',
    [req.params.courseId, req.session.userId],
    (err, course) => {
      if (err || !course) return res.status(404).json({ error: 'Course not found' });

      const newActive = course.active ? 0 : 1;
      db.run('UPDATE courses SET active = ? WHERE id = ?', [newActive, req.params.courseId], (err) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true, active: !!newActive });
      });
    }
  );
});

// --- Teacher Assessments ---

// get all assessments for a course
app.get('/api/teacher/assessments/:courseId', requireTeacher, (req, res) => {
  db.all(
    'SELECT * FROM assessments WHERE course_id = ? ORDER BY due_date ASC',
    [req.params.courseId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    }
  );
});

// teacher adds a new assessment to a course
app.post('/api/teacher/assessments', requireTeacher, (req, res) => {
  const { course_id, name, type, weight, total_marks, due_date } = req.body;
  if (!course_id || !name || !type || !weight || !total_marks) {
    return res.status(400).json({ error: 'All fields required' });
  }

  if (parseFloat(weight) <= 0 || parseFloat(weight) > 100) {
    return res.status(400).json({ error: 'Weight must be between 1 and 100' });
  }
  if (parseFloat(total_marks) <= 0) {
    return res.status(400).json({ error: 'Total marks must be positive' });
  }

  db.get(
    'SELECT id FROM courses WHERE id = ? AND teacher_id = ?',
    [course_id, req.session.userId],
    (err, course) => {
      if (err || !course) return res.status(403).json({ error: 'Not your course' });

      db.get(
        'SELECT SUM(weight) as total_weight FROM assessments WHERE course_id = ?',
        [course_id],
        (err, row) => {
          const currentWeight = row ? row.total_weight || 0 : 0;
          if (currentWeight + parseFloat(weight) > 100) {
            return res.status(400).json({ error: `Total weight would exceed 100% (currently at ${currentWeight}%)` });
          }

          db.run(`
            INSERT INTO assessments (course_id, name, type, weight, total_marks, due_date)
            VALUES (?, ?, ?, ?, ?, ?)
          `, [course_id, name.trim(), type, parseFloat(weight), parseFloat(total_marks), due_date || null], function(err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ success: true, id: this.lastID });
          });
        }
      );
    }
  );
});

// teacher deletes an assessment (checks they own the course first)
app.delete('/api/teacher/assessments/:assessmentId', requireTeacher, (req, res) => {
  db.get(`
    SELECT a.id FROM assessments a
    JOIN courses c ON c.id = a.course_id
    WHERE a.id = ? AND c.teacher_id = ?
  `, [req.params.assessmentId, req.session.userId], (err, row) => {
    if (err || !row) return res.status(403).json({ error: 'Not authorized' });

    db.run('DELETE FROM assessments WHERE id = ?', [req.params.assessmentId], (err) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true });
    });
  });
});

// returns anonymized completion stats for each assessment in a course
app.get('/api/teacher/courses/:courseId/stats', requireTeacher, (req, res) => {
  const courseId = req.params.courseId;

  db.get('SELECT COUNT(*) as enrolled FROM enrollments WHERE course_id = ?', [courseId], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });

    db.all(`
      SELECT a.id, a.name, a.type, a.weight, a.total_marks, a.due_date,
        COUNT(sa.student_id) as completed_count
      FROM assessments a
      LEFT JOIN student_assessments sa ON sa.assessment_id = a.id AND sa.status = 'Completed'
      WHERE a.course_id = ?
      GROUP BY a.id
    `, [courseId], (err, assessments) => {
      if (err) return res.status(500).json({ error: 'Database error' });

      const enrolled = row.enrolled;
      const enriched = assessments.map(a => ({
        ...a,
        completion_pct: enrolled > 0 ? Math.round(a.completed_count / enrolled * 100) : 0
      }));

      res.json({ enrolled, assessments: enriched });
    });
  });
});

// Reza part

// this is for the Students signup -Reza
app.post("/signup-student", (req, res) => {
  const { name, studentId, email, phone, program, password, confirmPassword } = req.body;

  if (!name || !studentId || !email || !phone || !program || !password || !confirmPassword) {
    return res.send("all fields are required");
  }

  if (password !== confirmPassword) {
    return res.send("passwords dont match");
  }

  db.get("SELECT id FROM users WHERE email = ?", [email], (err, existing) => {
    if (err) return res.send("database error");
    if (existing) return res.send("student already exists");

    bcrypt.hash(password, 10, (err, hash) => {
      if (err) return res.send("server error");

      db.run(
        "INSERT INTO users (name, email, password_hash, role, student_number, phone, program) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [cleanText(name), email, hash, "student", cleanText(studentId), cleanText(phone), cleanText(program)],
        function(err) {
          if (err) return res.send("database error");
          res.redirect("/S_Login.html");
        }
      );
    });
  });
});

// this is for the teachers signup -Reza
app.post("/signup-teacher", (req, res) => {
  const { name, teacherId, email, phone, phd, password, confirmPassword } = req.body;

  if (!name || !teacherId || !email || !phone || !phd || !password || !confirmPassword) {
    return res.send("all fields are required");
  }

  if (password !== confirmPassword) {
    return res.send("passwords dont match");
  }

  db.get("SELECT id FROM users WHERE email = ?", [email], (err, existing) => {
    if (err) return res.send("database error");
    if (existing) return res.send("teacher already exists");

    bcrypt.hash(password, 10, (err, hash) => {
      if (err) return res.send("server error");

      db.run(
        "INSERT INTO users (name, email, password_hash, role, teacher_number, phone, phd) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [cleanText(name), email, hash, "teacher", cleanText(teacherId), cleanText(phone), cleanText(phd)],
        function(err) {
          if (err) return res.send("database error");
          res.redirect("/T_Login.html");
        }
      );
    });
  });
});

// This is the student login -Reza
app.post("/login-student", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.send("email and password required");
  }

  db.get("SELECT * FROM users WHERE email = ? AND role = ?", [email, "student"], (err, user) => {
    if (err) return res.send("database error");
    if (!user) return res.send("no student found");

    bcrypt.compare(password, user.password_hash, (err, match) => {
      if (err) return res.send("server error");
      if (!match) return res.send("wrong password");

      req.session.userId = user.id;
      req.session.role = "student";
      req.session.name = user.name;

      res.redirect("/S_Home_Page.html");
    });
  });
});

// this is the teacher login -Reza
app.post("/login-teacher", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.send("email and password required");
  }

  db.get("SELECT * FROM users WHERE email = ? AND role = ?", [email, "teacher"], (err, user) => {
    if (err) return res.send("database error");
    if (!user) return res.send("no teacher found");

    bcrypt.compare(password, user.password_hash, (err, match) => {
      if (err) return res.send("server error");
      if (!match) return res.send("wrong password");

      req.session.userId = user.id;
      req.session.role = "teacher";
      req.session.name = user.name;

      res.redirect("/T_Home_Page.html");
    });
  });
});

// this is for forgot password -Reza
app.post("/forgot-password", (req, res) => {
  if (!transporter) return res.status(503).send("Password reset email is not configured. Set the SMTP environment variables.");
  const { email } = req.body;

  if (!email) {
    return res.send("email is required");
  }

  db.get("SELECT id FROM users WHERE email = ?", [email], (err, user) => {
    if (err) return res.send("database error");
    if (!user) return res.send("email not found");

    const code = makeCode();
    let codes = readResetCodes();

    const oldCode = codes.find(function(oneCode) {
      return oneCode.email === email;
    });

    if (oldCode) {
      oldCode.code = code;
      oldCode.verified = false;
    } else {
      codes.push({
        email: email,
        code: code,
        verified: false
      });
    }

    saveResetCodes(codes);

    const oldRedirect = res.redirect.bind(res);

    res.redirect = function(url) {
      transporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: email,
        subject: "Verification Code",
        text: "Your verification code is: " + code
      }, (error, info) => {
        if (error) {
          console.log(error);
          return res.send("email failed");
        }

        oldRedirect(url);
      });
    };


    res.redirect("/Email_Verification.html");
  });
});

// this is for email verification -Reza
app.post("/verify-email", (req, res) => {
  const email = req.body.email;
  const verificationCode = req.body.verificationCode;

  if (!email || !verificationCode) {
    return res.send("email and code are required");
  }

  let codes = readResetCodes();

  const savedCode = codes.find(function(oneCode) {
    return oneCode.email === email;
  });

  if (!savedCode) {
    return res.send("no code found for this email");
  }

  if (savedCode.code !== verificationCode) {
    return res.send("wrong verification code");
  }

  savedCode.verified = true;
  saveResetCodes(codes);

  res.redirect("/Reset_Password.html");
});

// this is to reset password - Reza
app.post("/reset-password", (req, res) => {
  const { email, newPassword, confirmPassword } = req.body;

  if (!email || !newPassword || !confirmPassword) {
    return res.send("all fields are required");
  }

  if (newPassword !== confirmPassword) {
    return res.send("passwords dont match");
  }

  let codes = readResetCodes();

  const savedCode = codes.find(function(oneCode) {
    return oneCode.email === email;
  });

  if (!savedCode || savedCode.verified !== true) {
    return res.send("you must verify your email first");
  }

  bcrypt.hash(newPassword, 10, (err, hash) => {
    if (err) return res.send("server error");

    db.run(
      "UPDATE users SET password_hash = ? WHERE email = ?",
      [hash, email],
      function(err) {
        if (err) return res.send("database error");
        if (this.changes === 0) return res.send("email not found");

        codes = codes.filter(function(oneCode) {
          return oneCode.email !== email;
        });

        saveResetCodes(codes);

        res.redirect("/Login_Front_Page.html");
      }
    );
  });
});

app.get('/resetpassword', (req, res) => {
  res.sendFile(path.join(__dirname, 'Reset_Password.html'));
});

app.get('/ResetPasswordStudent.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'Reset_Password.html'));
});


// this is to get all students with their grades for a course -Hanad
app.get('/api/teacher/grades/:courseId', requireTeacher, (req, res) => {
  const courseId  = req.params.courseId;
  const teacherId = req.session.userId;

  // this is to check if the course belongs to the teacher -Hanad
  db.get(
    'SELECT * FROM courses WHERE id = ? AND teacher_id = ?',
    [courseId, teacherId],
    (err, course) => {
      if (err)    return res.status(500).json({ error: 'Database error' });
      if (!course) return res.status(404).json({ error: 'Course not found' });

      // this is to get all assessments of the course -Hanad
      db.all(
        'SELECT * FROM assessments WHERE course_id = ? ORDER BY due_date ASC',
        [courseId],
        (err, assessments) => {
          if (err) return res.status(500).json({ error: 'Database error' });

          // this is to get all students enrolled in the course -Hanad
          db.all(`
            SELECT u.id as student_id, u.name, u.student_number
            FROM users u
            JOIN enrollments e ON e.student_id = u.id
            WHERE e.course_id = ?
            ORDER BY u.name ASC
          `, [courseId], (err, students) => {
            if (err) return res.status(500).json({ error: 'Database error' });

            if (!students.length) {
              return res.json({
                course_code: course.course_code,
                course_name: course.course_name,
                section:     course.section,
                term:        course.term,
                assessments,
                students: []
              });
            }

            // this is to get all grades for each student -Hanad
            const studentIds = students.map(s => s.student_id);

            db.all(`
              SELECT sa.student_id, sa.assessment_id, sa.earned_marks, sa.status
              FROM student_assessments sa
              WHERE sa.assessment_id IN (
                SELECT id FROM assessments WHERE course_id = ?
              )
              AND sa.student_id IN (${studentIds.map(() => '?').join(',')})
            `, [courseId, ...studentIds], (err, gradeRows) => {
              if (err) return res.status(500).json({ error: 'Database error' });

              // this is to organize grades in a lookup object -Hanad
              const lookup = {};
              gradeRows.forEach(row => {
                if (!lookup[row.student_id]) lookup[row.student_id] = {};
                lookup[row.student_id][row.assessment_id] = {
                  earned_marks: row.earned_marks,
                  status:       row.status
                };
              });

              // this is to compute overall and letter grades -Hanad
              const enrichedStudents = students.map(s => {
                const grades = lookup[s.student_id] || {};

                // this is to filter graded assessments -Hanad
                const graded = assessments.filter(a => {
                  const g = grades[a.id];
                  return g && g.earned_marks !== null && g.earned_marks !== undefined;
                });

                let overall = null;
                if (graded.length) {
                  const totalWeight = graded.reduce((sum, a) => sum + a.weight, 0);

                  // this is to calculate weighted sum -Hanad
                  const weightedSum = graded.reduce((sum, a) => {
                    const pct = grades[a.id].earned_marks / a.total_marks * 100;
                    return sum + pct * a.weight;
                  }, 0);

                  overall = totalWeight > 0
                    ? Math.round(weightedSum / totalWeight * 10) / 10
                    : null;
                }

                return {
                  student_id:     s.student_id,
                  name:           s.name,
                  student_number: s.student_number || '',
                  grades,
                  overall,
                  letter: letterGrade(overall)
                };
              });

              res.json({
                course_code: course.course_code,
                course_name: course.course_name,
                section:     course.section,
                term:        course.term,
                assessments,
                students:    enrichedStudents
              });
            });
          });
        }
      );
    }
  );
});

// this is to get all grades for a student -Hanad
app.get('/api/student/grades', requireStudent, (req, res) => {
  const studentId = req.session.userId;

  // this is to get all courses of the student -Hanad
  db.all(`
    SELECT c.*
    FROM courses c
    JOIN enrollments e ON e.course_id = c.id
    WHERE e.student_id = ?
    ORDER BY c.created_at DESC
  `, [studentId], (err, courses) => {
    if (err) return res.status(500).json({ error: 'Database error' });

    if (!courses.length) return res.json([]);

    // this is to get assessments and grades for each course -Hanad
    const promises = courses.map(course => new Promise(resolve => {
      db.all(`
        SELECT a.*, sa.earned_marks, sa.status as student_status
        FROM assessments a
        LEFT JOIN student_assessments sa
          ON sa.assessment_id = a.id AND sa.student_id = ?
        WHERE a.course_id = ?
        ORDER BY a.due_date ASC
      `, [studentId, course.id], (err, assessments) => {
        if (err) {
          resolve({ ...course, course_id: course.id, assessments: [], overall: null, letter: '—' });
          return;
        }

        // this is to calculate overall grade -Hanad
        const graded = assessments.filter(a =>
          a.earned_marks !== null && a.earned_marks !== undefined
        );

        let overall = null;
        if (graded.length) {
          const totalWeight = graded.reduce((s, a) => s + a.weight, 0);

          const weightedSum = graded.reduce((s, a) =>
            s + (a.earned_marks / a.total_marks * 100) * a.weight, 0);

          overall = totalWeight > 0
            ? Math.round(weightedSum / totalWeight * 10) / 10
            : null;
        }

        resolve({
          course_id:    course.id,
          course_code:  course.course_code,
          course_name:  course.course_name,
          section:      course.section,
          term:         course.term,
          teacher_name: course.teacher_name,
          assessments,
          overall,
          letter: letterGrade(overall)
        });
      });
    }));

    Promise.all(promises).then(result => res.json(result));
  });
});

// this is to convert percentage to letter grade -Hanad
function letterGrade(pct) {
  if (pct === null || pct === undefined) return '—';
  if (pct >= 90) return 'A+';
  if (pct >= 85) return 'A';
  if (pct >= 80) return 'A-';
  if (pct >= 77) return 'B+';
  if (pct >= 73) return 'B';
  if (pct >= 70) return 'B-';
  if (pct >= 67) return 'C+';
  if (pct >= 63) return 'C';
  if (pct >= 60) return 'C-';
  if (pct >= 57) return 'D+';
  if (pct >= 50) return 'D';
  return 'F';
}


app.put('/api/teacher/grades', requireTeacher, (req, res) => {
  const { student_id, assessment_id, earned_marks } = req.body;
 
  if (!student_id || !assessment_id) {
    return res.status(400).json({ error: 'student_id and assessment_id are required' });
  }
 
  db.get(`
    SELECT a.id, a.total_marks
    FROM assessments a
    JOIN courses c ON c.id = a.course_id
    WHERE a.id = ? AND c.teacher_id = ?
  `, [assessment_id, req.session.userId], (err, assessment) => {
    if (err)        return res.status(500).json({ error: 'Database error' });
    if (!assessment) return res.status(403).json({ error: 'Not authorized to grade this assessment' });
 
    // Validate marks range if provided
    if (earned_marks !== null && earned_marks !== undefined) {
      const marks = parseFloat(earned_marks);
      if (isNaN(marks) || marks < 0) {
        return res.status(400).json({ error: 'Earned marks must be a non-negative number' });
      }
      if (marks > assessment.total_marks) {
        return res.status(400).json({
          error: `Earned marks cannot exceed total marks (${assessment.total_marks})`
        });
      }
    }
 
    // Upsert into student_assessments
    // If a row already exists for this student+assessment, update it
    // If not, insert a new one and set status to Completed if marks were given
    const status = (earned_marks !== null && earned_marks !== undefined) ? 'Completed' : 'Pending';
 
    db.run(`
      INSERT INTO student_assessments (student_id, assessment_id, earned_marks, status)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(student_id, assessment_id) DO UPDATE SET
        earned_marks = excluded.earned_marks,
        status       = excluded.status,
        updated_at   = CURRENT_TIMESTAMP
    `, [student_id, assessment_id, earned_marks ?? null, status], (err) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true });
    });
  });
});
 
app.get('/api/debug/course/:courseId', requireTeacher, (req, res) => {
  const courseId = req.params.courseId;
  db.all(`
    SELECT u.id, u.name, u.role, u.student_number, e.course_id
    FROM enrollments e
    JOIN users u ON u.id = e.student_id
    WHERE e.course_id = ?
  `, [courseId], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ enrolled: rows });
  });
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
