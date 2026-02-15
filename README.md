# SecureScan

**SecureScan** is an AI-powered security intelligence platform that analyzes code, text, and images for vulnerabilities, phishing, deepfakes, and threats. Features a **FastAPI backend** with PostgreSQL, JWT auth, async Celery workers, and real LLM integration (OpenAI/Gemini).

![SecureScan Demo](assets/demo/demo.png)

## Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────┐
│  Frontend (JS)  │────▶│  FastAPI API  │────▶│  PostgreSQL │
│  index.html     │     │  /api/v1/     │     │  + Redis    │
└─────────────────┘     └──────┬───────┘     └─────────────┘
                               │
                    ┌──────────┴──────────┐
                    │  Analysis Engines   │
                    ├─────────────────────┤
                    │ • Code Analyzer     │
                    │ • Text Analyzer     │
                    │ • Image Analyzer    │
                    │ • LLM Engine        │
                    │ • Celery Worker     │
                    └─────────────────────┘
```

## Key Features

- **Code Analysis**: Taint tracking, 20+ OWASP rules, RCE detection, exploit examples, remediation snippets
- **Text Analysis**: Phishing/URL detection, typosquatting (Levenshtein), homoglyphs, social engineering, AI text detection
- **Image Analysis**: ELA, LBP texture, bilateral symmetry, GAN artifacts, chromatic aberration, multi-signal fusion
- **LLM Integration**: OpenAI GPT-4o / Gemini 1.5 Pro / Mock mode
- **JWT Authentication**: Register, login, token refresh, user profiles
- **Dashboard**: Scan history, severity breakdown, type analytics
- **Docker**: One-command deployment with PostgreSQL, Redis, FastAPI, Celery

## Quick Start

### Option 1: Docker (Recommended)

```bash
# Clone and start everything
git clone https://github.com/Harshaghera111/SecureScan.git
cd SecureScan

# Create backend .env from template
cp backend/.env.example backend/.env

# Start all services
docker-compose up --build
```

Services:
- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Frontend**: Open `index.html` in browser

### Option 2: Local Development

```bash
# Prerequisites: Python 3.12+, PostgreSQL, Redis

# Backend
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
cp .env.example .env         # Edit with your settings
uvicorn app.main:app --reload

# Frontend
# Open index.html in browser, or use Live Server
```

## API Endpoints

| Method   | Endpoint                   | Auth     | Description              |
| -------- | -------------------------- | -------- | ------------------------ |
| `POST`   | `/api/v1/auth/register`    | No       | Register new user        |
| `POST`   | `/api/v1/auth/login`       | No       | Login, get JWT tokens    |
| `POST`   | `/api/v1/auth/refresh`     | No       | Refresh access token     |
| `GET`    | `/api/v1/auth/me`          | Yes      | Get user profile         |
| `POST`   | `/api/v1/scans/`           | Optional | Run a security scan      |
| `GET`    | `/api/v1/scans/history`    | Yes      | Get scan history         |
| `GET`    | `/api/v1/scans/{id}`       | Yes      | Get scan result          |
| `DELETE` | `/api/v1/scans/{id}`       | Yes      | Delete a scan            |
| `GET`    | `/api/v1/scans/stats/dashboard` | Yes | Dashboard analytics |

## Tech Stack

- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **Backend**: Python 3.12, FastAPI, SQLAlchemy 2.0, Pydantic v2
- **Database**: PostgreSQL 16, Redis 7
- **Auth**: JWT (access + refresh tokens), bcrypt
- **AI**: OpenAI GPT-4o, Google Gemini 1.5 Pro, Pillow, NumPy
- **DevOps**: Docker, Docker Compose, Celery

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open-source and available under the [MIT License](LICENSE).
