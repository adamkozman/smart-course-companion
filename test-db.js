const db = require('./db');

db.all("SELECT * FROM student_assessments", [], (err, rows) => {
  if (err) {
    console.error(err);
    return;
  }
  console.log(rows);
});