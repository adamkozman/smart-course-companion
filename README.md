# Smart Course Companion

A course management web application built by a team of four as a class project. Students can join courses, track assessments, view grades and use an assessment calendar. Instructors can manage courses, create assessments and record grades.

**Original project completion: April 4, 2026.** This date is based on the final project folder and its source-file timestamps. Repository preparation took place on October 9, 2026; Git commits are not backdated.

## Team

- Adam Kozman — courses and assessment creation and management.
- Matteo Carmosino — integration and end-to-end testing.
- Reza Ahsan — login, signup, password reset and email verification.
- Hanad Moustapha Ahmed — student/instructor grades, calendar and grade initialization.

Contribution descriptions reflect the original source comments and team-provided details. This is a collaborative course project.

## Features

- Separate student and instructor accounts and dashboards.
- Course creation, enrollment and assessment management.
- Weighted grades and instructor grade entry.
- Assessment calendar and editable account profiles.
- Email-based password reset when SMTP is configured.

## Technology

HTML, CSS and JavaScript frontend; Node.js and Express backend; SQLite storage; bcrypt password hashing; Express sessions; Nodemailer for reset email.

## Run locally

Use Node.js 22 or newer and npm.

```sh
npm ci
npm start
```

Open http://localhost:3000. The application creates a fresh SQLite database automatically. Create your own instructor and student accounts; no saved accounts are included.

To try the main workflow, create an instructor account, create a course and an assessment, then log out and register a student. Join the course using its exact code, section and term. The instructor can enter grades and the student can view them.

## Optional configuration

Copy `.env.example` to `.env`. Set `SESSION_SECRET` to a long random string to retain sessions across restarts. Without it, a random secret is generated at startup. `PORT` defaults to 3000.

Password-reset email requires your own `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER` and `SMTP_PASS`. Use `SMTP_SECURE=true` for implicit TLS (usually port 465), and set `SMTP_FROM` if your provider requires a specific sender. Without SMTP configuration, the rest of the app works and password reset returns an explanatory message.

## Repository layout

- `server.js` — server, authentication and application API routes.
- `db.js` — database schema and initialization.
- `S_*.html` / `T_*.html` — student and instructor pages.
- `Grades.html` / `Assessments_Calendar.html` — grades and calendar views.
- `Styles/`, `Icons/`, `public/js/` — frontend assets and shared API utilities.

## Publication notes

This repository uses the April 4 final project source. Publication cleanup removed embedded mail credentials and local account/reset data, added environment configuration, and restricted static serving to frontend assets. Local databases, dependencies and `.env` files are excluded from Git.

This is an educational prototype intended for local demonstration. The original authorization and password-reset flows require further review before production deployment. No open-source license has been added on behalf of the team.

## Validation

Checked during repository preparation on October 9, 2026:

- Clean dependency installation with `npm ci`.
- Server/database JavaScript and all 10 inline browser scripts pass syntax checks.
- Local HTTP integration checks pass for registration, course and assessment creation, enrollment, instructor grade entry, and student weighted-grade calculation.
- Requests for server source, database, environment configuration and package configuration return 404.
- Password reset returns 503 with an explanation when SMTP is not configured.

Integration checks used synthetic accounts and Windows named-pipe HTTP transport because loopback TCP connections were unavailable in the preparation environment. Test account data is not included. Browser interactions and real SMTP delivery have not been tested.

