# 304Tracker Flask Application

**A real-time logging and leaderboard web application for the Tamil card game 304**

---

## Introduction

304Tracker is a web application designed to provide a platform for players of the Tamil card game 304. It allows users to log games in real-time, view player statistics, and access a leaderboard.

---

## Features

- User authentication (login and registration)
- Real-time game logging
- Live dashboard for player statistics
- Leaderboard view for top players

---

## Project Structure

```
304tracker-flask
├── app
│   ├── __init__.py
│   ├── models.py
│   ├── routes
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   ├── game.py
│   │   └── dashboard.py
│   ├── static
│   │   └── style.css
│   ├── templates
│   │   ├── base.html
│   │   ├── login.html
│   │   ├── dashboard.html
│   │   ├── leaderboard.html
│   │   └── game_log.html
│   └── utils.py
├── migrations
│   └── README.md
├── requirements.txt
├── config.py
├── run.py
└── README.md
```

---

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd 304tracker-flask
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

4. Set up the database:
   ```
   flask db init
   flask db migrate
   flask db upgrade
   ```

5. Run the application:
   ```
   python run.py
   ```

---

## Usage

- Navigate to `http://localhost:5000` in your web browser.
- Register a new account or log in with an existing account.
- Create or join a game to start logging stones in real-time.
- Access the dashboard to view player statistics and the leaderboard.

---

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for any suggestions or improvements.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.