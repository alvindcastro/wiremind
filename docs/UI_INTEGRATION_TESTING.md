# UI Integration Testing Guide (U7.7)

This guide provides the necessary Docker commands to verify the integration between the `wiremind` (Go backend) and `wiremind-ui` (React frontend) repositories, following the setup in Phase 7.

## Prerequisites

- **Wiremind (Backend):** `C:\Users\alvin\GolandProjects\wiremind`
- **Wiremind UI (Frontend):** `C:\Users\alvin\WebstormProjects\wiremind-ui`
- Docker and Docker Compose installed.

## 1. Build and Start the Stack

From the `wiremind` repository root:

```powershell
# Build the UI service specifically (verifies the Dockerfile and build context)
docker compose build wiremind-ui

# Build all other services
docker compose build forensics worker agents

# Start the core stack (forensics, postgres, redis, and wiremind-ui)
docker compose up forensics postgres redis wiremind-ui
```

> **Note:** The `docker-compose.override.yaml` automatically handles the path to `WebstormProjects\wiremind-ui`.

## 2. Verification Steps (Smoke Test)

Perform these checks in your browser:

### UI Accessibility
- **URL:** `http://localhost:3001`
- **Expected:** The React application loads correctly (no blank screen).

### Data Rendering
- **Page:** Navigate to **Flows** (`/flows`).
- **Expected:** The table renders with data fetched from the `forensics` API (proxied via Nginx).

### Console Check
- **Action:** Open Browser DevTools (`F12`) -> **Console**.
- **Expected:** No CORS errors or failed requests to `/api/*`.

### Deep Linking
- **Action:** Navigate to `/threats` and refresh the page.
- **Expected:** The page reloads correctly (verifies Nginx `try_files` configuration).

## 3. Useful Commands

### Check Container Logs
```powershell
# View logs for the UI and Backend
docker compose logs -f wiremind-ui forensics
```

### Restart a Specific Service
```powershell
docker compose restart wiremind-ui
```

### Stop and Cleanup
```powershell
docker compose down
```

## Troubleshooting

- **Build Context Error:** If Docker complains it cannot find the `wiremind-ui` directory, verify that `WebstormProjects` and `GolandProjects` share the same parent directory.
- **Empty Flows Table:** Ensure `postgres` is healthy and the `forensics` service has processed some data or the database is seeded.
