# One-Tap

One-Tap is a voice-first demo for older adults to prepare everyday service requests and coordinate family review. Its visual direction follows the attached Stitch page designs: high-contrast green palette, large type, clear buttons, and simple language.

## Run locally

Requirements: Node.js 24 or newer. The app uses Node's built-in SQLite module and has no third-party runtime dependencies.

```sh
npm start
```

Open http://localhost:3000. SQLite creates `data/one-tap.sqlite` and the tables on first launch. Set `PORT` and `DATABASE_PATH` in your shell to change the port or database file. The `.env.example` file lists optional integration names; this app does not load a `.env` file and does not use those integration variables.

Create an account with a unique email and a password of at least 12 characters. Choose Older adult or Family member. For family access, the older adult creates a one-time invitation code, shares it directly, and the family member signs up and accepts it with explicit consent.

## What works in this demo

- Local account creation, sign-in, sign-out, password hashing, and server-side sessions.
- Profile and accessibility preferences, including phone, saved addresses, language, text size, contrast, voice-guidance preference, and in-app notification preference.
- Explicit family invitations, manager/viewer roles, and consent before a family link is created.
- Service categories, permission settings, confirmed demo requests, status history, request cancellation, and family approval, decline, or clarification.
- Browser speech recognition when the browser offers it. Typed requests remain available as a fallback.

Request interpretation is a deterministic keyword demo in `server.js`; the UI labels it DEMO. Request text is stored for the request and its timeline and deleted after 90 days by a daily cleanup. Audio is not uploaded to this application.

## What is not connected

No AI, email/SMS notification, provider, booking, payment, purchase, live supervision, or live provider-tracking integration is configured. A request marked “Ready for provider connection” is only a saved demo request. Approval does not place an order or booking. Pending approvals remain visible in the app; no message is sent. Browser speech recognition is an optional browser feature, not a One-Tap speech service.

## Authentication and production setup

The included password authentication is a local development path, not production-ready identity verification. Before real users or personal data are introduced, replace it with a reviewed identity provider and verified email/phone flows; serve only over HTTPS; use secure session/key management; add persistent distributed rate limiting, operational monitoring, tested backups, and a privacy/retention review. Configure a real notification provider and a verified service provider only after their consent, security, and failure behavior are implemented and tested. Never store payment card details.

This repository was empty before the demo was added. It has no pre-existing framework, database, migrations, authentication service, or frontend source to preserve. The app therefore uses Node's built-in HTTP server, built-in SQLite, and a small vanilla HTML/CSS/JS frontend rather than introducing another framework. The Stitch HTML attachment was used as a design reference; static sample identities and unverified tracking/booking claims were not carried into the app.

## Tests

Run `npm test` with Node.js 24 or newer. Tests exercise local registration/session behavior, request confirmation, permission enforcement, invitation consent, family approval, and account isolation.
