# AHELP Website

This project serves the AHELP wellness application. It uses an Express server with a SQLite database and static front-end files.

## API Endpoints

- `POST /api/assessments` – store a user's health assessment.
- `GET /api/progress?user_id={id}` – retrieve weekly minutes and monthly steps for charts.
- `POST /api/progress` – update progress arrays.
- `GET /api/challenges?user_id={id}` – list saved challenges.
- `POST /api/challenges` – create a challenge entry.
- `GET /api/rewards?user_id={id}` – fetch reward history and current point balance.
- `POST /api/rewards` – record points earned or redeemed.

Run the server with:

```sh
npm start
```
