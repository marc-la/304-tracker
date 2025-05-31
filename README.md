# 304Tracker

**A real-time logging and leaderboard web application for the Tamil card game 304**

---

## Introduction

304Tracker provides a comprehensive platform to:

- Register and authenticate users
- Create and join 4-player matches
- Automatically form teams and configure “best of _x_ stones”
- Record each stone’s bidder, trump value (160, 170, 220, 250, PCC), and outcome
- Display live-updating player statistics and a global leaderboard

---

## Feasibility & Timeline

**Technical Capabilities**

- Full-stack development experience
- Real-time communication (WebSockets)
- Relational database design and ORM migrations

**Project Phases**

| Phase   | Duration   | Deliverables                                                         |
|---------|------------|----------------------------------------------------------------------|
| Phase 1 | 2–3 weeks  | User authentication, match creation, stone logging, basic CRUD       |
| Phase 2 | 2 weeks    | Statistics calculations, leaderboard queries, analytics pages        |
| Phase 3 | 1–2 weeks  | Real-time updates, polished dashboard UI, testing and deployment     |

---

## Functional Requirements

1. **Authentication & Authorization**  
   - Email/password with JWT or OAuth  
   - Role-based access control (admin, player)

2. **Match Setup & Entry**  
   - Create a match with four players → auto-assign two teams  
   - Select “best of _x_ stones”  
   - Record for each stone: bidder, trump value, win/loss

3. **Statistics & Leaderboard**  
   - Per-player aggregates: games played, stones won, average trump value, win rate  
   - Global leaderboard sortable by win rate, total points, etc.

4. **Real-Time Updates**  
   - Instant dashboard refresh via WebSockets

5. **Dashboard Views**  
   - **Player Profile**: performance charts and trends  
   - **Leaderboard**: top N players with key metrics  
   - **Match History**: searchable and filterable list of recent games

---

## Technology Stack

| Layer            | Technology                   | Rationale                                    |
|------------------|------------------------------|----------------------------------------------|
| Frontend         | React + Tailwind CSS         | Component-driven, responsive styling         |
| State Management | Redux or React Query         | Global state handling and caching            |
| Backend API      | Node.js + Express or NestJS  | Modular, middleware support                  |
| Real-Time Layer  | Socket.IO                    | Bidirectional, event-based communication     |
| Database         | PostgreSQL                   | ACID compliance, relational integrity        |
| ORM              | Prisma or TypeORM            | Type-safe schema, migration support          |
| Authentication   | JWT or Auth0                 | Secure token management                      |
| Deployment       | Docker + Kubernetes / Heroku | Containerization and scalable hosting        |
| CI/CD            | GitHub Actions               | Automated testing and deployment pipelines   |

---

## Architecture Overview

```pgsql
[React SPA] ←→ [REST + WebSocket API] ←→ [PostgreSQL]
│ ↑
└─> [Authentication Service / JWT] ─┘
```


- **React SPA**: Routes for login, dashboard, player profiles, and match creation  
- **API Server**: REST endpoints, Socket.IO namespaces, authentication middleware  
- **Database**: Core tables and materialized views for efficient statistics

---

## Database Schema (Draft)

```sql
-- Users & Roles
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'player'
);

-- Matches & Players
CREATE TABLE matches (
  id SERIAL PRIMARY KEY,
  created_by INTEGER REFERENCES users(id),
  date TIMESTAMP DEFAULT NOW(),
  best_of_stones INTEGER NOT NULL
);

CREATE TABLE match_players (
  match_id INTEGER REFERENCES matches(id),
  user_id INTEGER REFERENCES users(id),
  team INTEGER CHECK (team IN (1,2)),
  PRIMARY KEY (match_id, user_id)
);

-- Stones (Rounds)
CREATE TABLE stones (
  id SERIAL PRIMARY KEY,
  match_id INTEGER REFERENCES matches(id),
  stone_number INTEGER NOT NULL,
  trump_value INTEGER NOT NULL,
  bidder_id INTEGER REFERENCES users(id),
  winning_team INTEGER CHECK (winning_team IN (1,2))
);
```

---

## UI/UX Outline

- **Login / Signup**: Clean, accessible forms
- **New Match Wizard**:
    1. Select four players (autocomplete search)
    2. Choose stones count
    3. Enter each stone’s details via a stepper interface
- **Dashboard**:
  -   Statistic cards (games, stones, average trump, win rate)
  -   Line chart of performance over time
  -   Leaderboard table (sortable, paginated)
- **Match History**: Filterable table with match details

---

## Real-Time Update Flow

1. Client establishes Socket.IO connection post-authentication
2. Joins `stats` and `matches` channels
3. On new stone entry (via REST), server emits:
  ```js
  io.to('stats').emit('statsUpdated', { playerId, newStats });
  io.to('matches').emit('matchUpdated', { matchId, stone });
  ```
4. Clients update UI state and re-render live data

---

## Next Steps & MVP

1. MVP
  - User authentication
  - Match creation and stone logging
  - Basic player statistics and leaderboard
2. Phase 2
  - Real-time dashboard updates
  - Advanced analytics (filters, head-to-head metrics)
  - Responsive design
3. Phase 3
  - Social features (friends, challenges)
  - Data export (CSV, PDF)
  - Full CI/CD pipeline and monitoring

---

Contributions and feedback are welcome. Let’s build the definitive 304 tracking and analytics platform!
