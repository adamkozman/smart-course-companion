const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const db = new sqlite3.Database(path.join(__dirname, 'scc.db'));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('student','teacher')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_code TEXT NOT NULL,
    course_name TEXT NOT NULL,
    section TEXT NOT NULL,
    term TEXT NOT NULL,
    teacher_id INTEGER NOT NULL,
    teacher_name TEXT NOT NULL,
    active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(teacher_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS enrollments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
    enrolled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(student_id, course_id),
    FOREIGN KEY(student_id) REFERENCES users(id),
    FOREIGN KEY(course_id) REFERENCES courses(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    weight REAL NOT NULL,
    total_marks REAL NOT NULL,
    due_date TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(course_id) REFERENCES courses(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS student_assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    assessment_id INTEGER NOT NULL,
    earned_marks REAL,
    status TEXT DEFAULT 'Pending',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(student_id, assessment_id),
    FOREIGN KEY(student_id) REFERENCES users(id),
    FOREIGN KEY(assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
  )`);

  db.all('PRAGMA table_info(users)', (err, columns) => {
    if (err) {
      console.error('Could not read users table info:', err.message);
      return;
    }

    const existingColumns = columns.map(function(column) {
      return column.name;
    });

    const missingColumns = [
      { name: 'student_number', definition: 'TEXT' },
      { name: 'teacher_number', definition: 'TEXT' },
      { name: 'phone', definition: 'TEXT' },
      { name: 'program', definition: 'TEXT' },
      { name: 'phd', definition: 'TEXT' }
    ].filter(function(column) {
      return !existingColumns.includes(column.name);
    });

    missingColumns.forEach(function(column) {
      db.run(
        'ALTER TABLE users ADD COLUMN ' + column.name + ' ' + column.definition,
        function(alterError) {
          if (alterError) {
            console.error('Could not add column ' + column.name + ':', alterError.message);
          }
        }
      );
    });
  });
});

module.exports = db;
