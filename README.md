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

## Environment Variables

Create a `.env` file (or copy from `.env.example`) to configure secrets and runtime options:

```
PORT=3000
JWT_SECRET=change_me
DB_FILE=users.db
FRONTEND_DIR=improved-website-v14
# SSL_KEY=path/to/key.pem
# SSL_CERT=path/to/cert.pem
```

## Scripts

- `npm run build:frontend` – copy static assets into a `public` directory.
- `npm run serve:frontend` – serve the built front-end from `public/`.
- `npm run serve:backend` – run the API server.
- `npm run build` – run the front-end build step.

## Deployment

### Heroku
1. `heroku create`
2. `heroku config:set JWT_SECRET=your_secret`
3. `git push heroku main`
4. `heroku open`

### Render
1. Create a new Web Service from this repository.
2. Set environment variables in the Render dashboard.
3. Build command: `npm run build`
4. Start command: `npm run serve:backend`

### AWS (Elastic Beanstalk)
1. Install the AWS EB CLI and run `eb init`.
2. Configure environment variables in the EB console or via `eb setenv`.
3. Deploy with `eb deploy`.
