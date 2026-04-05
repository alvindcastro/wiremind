# UI Plan — wiremind-ui

A dedicated frontend for the Wiremind network forensics platform.

> API backend: Go REST server at `:8765`
> Spec: `docs/openapi.yaml` (OpenAPI 3.0.3)
> IDE: WebStorm
> Repo: separate (`wiremind-ui`) — can live alongside `wiremind` in the same workspace

---

## Decision: Separate repo

Keeps Go and frontend concerns cleanly separated. The UI is a static SPA that
talks to the Go API over HTTP. It can be:

- Run locally against a local `wiremind` stack
- Served as a static build from any CDN or nginx
- Added as a `ui` service in `docker-compose.yaml` (Phase 7)

---

## Tech Stack

| Concern | Choice | Why |
|---|---|---|
| Framework | **React 19 + Vite** | SPA only (no SSR needed), fast HMR, WebStorm support |
| Language | **TypeScript** (strict) | Correctness, IDE autocomplete |
| Styling | **Tailwind CSS v3 + shadcn/ui** | Dark-mode first, copy-paste components, no runtime CSS |
| Data fetching | **TanStack Query v5** | Caching, background refetch, SSE integration |
| Tables | **TanStack Table v8** | Column filtering, sorting, virtualization for large datasets |
| Routing | **React Router v6** | File-based style patterns, nested layouts |
| API client | **openapi-typescript + openapi-fetch** | Generated from `docs/openapi.yaml` — fully type-safe, zero boilerplate |
| Charts | **Recharts** | React-native, composable, lightweight |
| Network graph | **Cytoscape.js** | Handles hundreds of nodes, mature, good layout algorithms |
| Forms | **React Hook Form + Zod** | Type-safe validation, minimal re-renders |
| SSE (job stream) | Native `EventSource` API | No library needed |

### Why openapi-typescript over manual types

The Go server already has `docs/openapi.yaml`. Running:

```bash
npx openapi-typescript ../wiremind/docs/openapi.yaml -o src/api/schema.d.ts
```

produces typed path/method/request/response contracts. Combined with `openapi-fetch`,
every API call is statically checked against the spec. When the spec changes,
re-running the command immediately surfaces breakage in the TypeScript compiler.

---

## Repo Structure

```
wiremind-ui/
├── src/
│   ├── api/
│   │   ├── schema.d.ts          # generated — DO NOT edit by hand
│   │   └── client.ts            # createClient() wrapper around openapi-fetch
│   ├── components/
│   │   ├── ui/                  # shadcn/ui primitives (Button, Badge, Dialog, etc.)
│   │   ├── layout/
│   │   │   ├── Shell.tsx        # outer wrapper: sidebar + header + outlet
│   │   │   ├── Sidebar.tsx      # nav links
│   │   │   └── Header.tsx       # breadcrumb, global search, status badge
│   │   ├── tables/
│   │   │   └── DataTable.tsx    # generic TanStack Table wrapper
│   │   ├── ThreatBadge.tsx      # score chip (green/amber/red)
│   │   ├── GeoFlag.tsx          # country flag + ASN tooltip
│   │   └── JobStatusBadge.tsx   # pending/processing/completed/failed pill
│   ├── pages/
│   │   ├── Dashboard.tsx        # stats cards + recent jobs + top threats
│   │   ├── Flows.tsx            # enriched flows table
│   │   ├── Threats.tsx          # malicious findings table
│   │   ├── DNS.tsx
│   │   ├── TLS.tsx
│   │   ├── HTTP.tsx
│   │   ├── ICMP.tsx
│   │   ├── Jobs.tsx             # job list + submit form
│   │   ├── JobDetail.tsx        # SSE live stream + metadata
│   │   ├── NetworkGraph.tsx     # Cytoscape IP relationship graph
│   │   └── Config.tsx           # IOC management + pipeline settings
│   ├── hooks/
│   │   ├── useSSE.ts            # typed EventSource hook
│   │   └── useApiClient.ts      # singleton client with base URL
│   ├── lib/
│   │   ├── utils.ts             # cn() helper, formatters
│   │   └── threatColor.ts       # score → colour mapping
│   ├── App.tsx                  # router, QueryClientProvider
│   └── main.tsx
├── public/
├── nginx.conf                   # production nginx config (Phase 7)
├── Dockerfile                   # multi-stage node → nginx (Phase 7)
├── .dockerignore                # (Phase 7)
├── vite.config.ts               # dev proxy: /api → http://localhost:8765
├── tailwind.config.ts
├── components.json              # shadcn/ui config
├── tsconfig.json
└── package.json
```

---

## Pages & Features

| Route | Page | Key features |
|---|---|---|
| `/` | Dashboard | Stats cards, protocol breakdown doughnut, top-5 threat IPs, recent jobs widget |
| `/flows` | Flows | Table: src_ip/dst_ip/port/protocol/entropy/beacon/threat score. Filters: src_ip, dst_ip, protocol, job_id |
| `/threats` | Threats | Malicious flows only, sorted by threat_score desc, IOC match details |
| `/dns` | DNS Events | Table + domain search. Expandable row shows full question/answer records |
| `/tls` | TLS Events | Table + SNI search. Highlight weak ciphers |
| `/http` | HTTP Events | Table + host search. Flag CLI user-agents |
| `/icmp` | ICMP Events | Table with type/code descriptions |
| `/jobs` | Jobs | List of jobs + "Submit PCAP" drawer. Status badges, timestamps |
| `/jobs/:id` | Job Detail | Live SSE progress feed, packet/flow count, error display |
| `/graph` | Network Graph | Cytoscape canvas: nodes=IPs, edges=flows, red=malicious |
| `/config` | Config | IOC CRUD table, pipeline key/value editor, live capture start/stop |

---

## Pre-requisite: CORS on the Go server

> **Status: ✅ Done** — `corsMiddleware` is implemented in `internal/api/server.go`.
> Configurable via `config.yaml` `cors.allowed_origins` or `CORS_ALLOWED_ORIGINS` env var.
> No code changes needed before starting UI work.

The middleware wraps the mux and handles OPTIONS preflight. To allow the Vite dev server,
add `http://localhost:5173` to `CORS_ALLOWED_ORIGINS` in your `.env`:

```
CORS_ALLOWED_ORIGINS=http://localhost:5173,http://localhost:3001
```

---

## Phase Breakdown

### Phase 1 — Scaffold & Plumbing ✅
*Goal: empty app talking to the live API with correct types.*

- [x] **U1.1** Create `wiremind-ui` repo, init Vite + React + TypeScript
- [x] **U1.2** Install and configure Tailwind CSS + shadcn/ui (dark mode default)
- [x] **U1.3** Install `openapi-typescript` + `openapi-fetch`; add `generate:api` npm script pointing at `../wiremind/docs/openapi.yaml`
- [x] **U1.4** Run codegen; commit `src/api/schema.d.ts`
- [x] **U1.5** Write `src/api/client.ts` — `createClient<paths>` with base URL from `VITE_API_URL` env var
- [x] **U1.6** Configure Vite dev proxy: `/api → http://localhost:8765`, `/openapi.yaml → http://localhost:8765`
- [x] **U1.7** ~~Add CORS middleware to Go server~~ — already done in `internal/api/server.go`; add `http://localhost:5173` to `CORS_ALLOWED_ORIGINS` in `.env`
- [x] **U1.8** Install React Router v6; create Shell layout (sidebar + header + `<Outlet />`)
- [x] **U1.9** Add placeholder routes for all 10 pages; confirm navigation works
- [x] **U1.10** Add TanStack Query `QueryClientProvider` to `App.tsx`
- [x] **U1.11** Configure `.gitignore` and project cleanup

**Deliverable:** `npm run dev` → shell with nav. `curl /health` from browser network tab returns 200.

---

### Phase 2 — Core Data Tables ✅
*Goal: all six data-view pages showing live data with column filters.*

- [x] **U2.1** Build generic `<DataTable>` component with TanStack Table (column def props, client-side filter, sort, pagination)
- [x] **U2.2** Add `<ThreatBadge score={n} />` component (0–33 green, 34–66 amber, 67–100 red)
- [x] **U2.3** **Flows page** — columns: flow_id, src_ip:port → dst_ip:port, protocol, packets, bytes, entropy, is_beacon, threat_score. Filter bar: src_ip, dst_ip, protocol, job_id
- [x] **U2.4** **Threats page** — reuse Flows table filtered to `is_malicious=true`, add IOC match detail in expandable row
- [x] **U2.5** **DNS page** — columns: timestamp, query name, qtype, rcode, answer count. Search bar for domain. Expandable row shows full answers + threat context
- [x] **U2.6** **TLS page** — columns: timestamp, SNI, version, cipher, is_malicious. Highlight weak ciphers (RC4/export) in amber. Search bar for SNI
- [x] **U2.7** **HTTP page** — columns: timestamp, method, host, path, user_agent, status_code. Highlight CLI agents. Search bar for host
- [x] **U2.8** **ICMP page** — columns: timestamp, src_ip, dst_ip, type_name, code, size

**Deliverable:** All six tables populated with real data. Filters working.

---

### Phase 3 — Job Management & SSE
*Goal: full job lifecycle from submit → watch → view results.*

- [ ] **U3.1** **Jobs list page** — table with job_id, status badge, input_path, created_at, packet_count, flow_count
- [ ] **U3.2** "Submit PCAP" side drawer — form with `input_path` text field + optional `output_path`. React Hook Form + Zod validation. On submit POST `/api/v1/jobs`, redirect to job detail
- [ ] **U3.3** **Job detail page** — metadata card + live SSE feed
- [ ] **U3.4** `useSSE(jobId)` hook — wraps `EventSource` for `/api/v1/jobs/{id}/stream`. Returns current `Job` state and `isComplete` flag
- [ ] **U3.5** SSE progress UI — animated progress bar while `status === "processing"`, tick/cross on completion/failure, error message display
- [ ] **U3.6** "View Results" button on completed job — links to `/flows?job_id=<id>`

**Deliverable:** Submit a PCAP path, watch it process in real time, click through to results.

---

### Phase 4 — Dashboard
*Goal: at-a-glance overview of the current dataset.*

- [ ] **U4.1** Stats row — five cards (Flows, DNS, TLS, HTTP, ICMP counts) from `GET /api/v1/stats`. Auto-refresh every 30s via TanStack Query
- [ ] **U4.2** Protocol distribution doughnut (Recharts `PieChart`) — shows relative share of each protocol event type
- [ ] **U4.3** Recent jobs widget — last 5 jobs with status badge and relative timestamp
- [ ] **U4.4** Top threats list — top 5 flows by threat_score from `GET /api/v1/threats?limit=5`, each row shows src→dst and score badge
- [ ] **U4.5** Beacon detections counter — count of flows where `is_beacon=true` from in-memory flows

**Deliverable:** `/` shows a meaningful summary without navigating anywhere.

---

### Phase 5 — Network Graph
*Goal: visual IP relationship explorer.*

- [ ] **U5.1** Install `cytoscape` + `react-cytoscapejs`
- [ ] **U5.2** Build `<NetworkGraph>` component — transform `EnrichedFlow[]` into Cytoscape node/edge format
  - Node = IP address; edge = flow (directed)
  - Node colour: red=malicious, amber=suspicious (score>33), grey=clean
  - Edge width proportional to byte_count
- [ ] **U5.3** Layout: `cose-bilkent` for organic force-directed layout (install `cytoscape-cose-bilkent`)
- [ ] **U5.4** Click a node → side panel showing all flows for that IP, GeoIP info, IOC matches
- [ ] **U5.5** Filter controls: show only malicious, show only beaconing, filter by job_id
- [ ] **U5.6** Performance: only render top N flows by byte_count if total > 500 nodes (add "show all" toggle)

**Deliverable:** `/graph` renders the IP topology. Malicious nodes are red. Click reveals details.

---

### Phase 6 — Config & Control
*Goal: manage IOCs and pipeline settings from the UI.*

- [ ] **U6.1** **IOC table** — list all entries from `GET /api/v1/config/ioc`. Columns: indicator, type, severity badge, source, tags, created_at, delete button
- [ ] **U6.2** "Add IOC" dialog — form for indicator, type (ip/domain/hash), severity, source, tags (comma-separated). POST `/api/v1/config/ioc`
- [ ] **U6.3** Delete IOC — confirmation popover before `DELETE /api/v1/config/ioc/{id}`
- [ ] **U6.4** Pipeline config editor — key/value table. Inline edit → `PATCH /api/v1/config/pipeline`. Known keys shown with descriptions
- [ ] **U6.5** Live capture card — interface name input + BPF filter input. "Start" button → POST `/api/v1/capture/start`. "Stop" button → POST `/api/v1/capture/stop`

**Deliverable:** Full IOC CRUD. Can start/stop a live capture from the browser.

---

### Phase 7 — Docker Integration (Option B)
*Goal: `docker compose up` boots the full stack including the React UI served via nginx. One command, everything running.*

#### Architecture
```
Browser → nginx :3001
              ├─ /          → serves dist/ (React SPA, with SPA fallback)
              └─ /api/      → proxy_pass http://forensics:8765/
```

nginx proxies `/api` internally — the browser sees one origin, so no CORS headers
are needed in production. Dev workflow (`npm run dev` + Vite proxy) is unchanged.

#### Repo layout
```
~/GolandProjects/
  wiremind/          ← Go backend (docker-compose lives here)
  wiremind-ui/       ← React frontend (docker-compose references ../wiremind-ui)
```

#### Tasks

- [ ] **U7.1** `wiremind-ui`: Create `Dockerfile` (multi-stage)
  - Stage 1 (`builder`): `node:20-alpine`, copy `package*.json`, `npm ci`, `npm run build`
  - Stage 2 (`runtime`): `nginx:1.27-alpine`, copy `dist/` to `/usr/share/nginx/html`
  - Copy `nginx.conf` into image at `/etc/nginx/conf.d/default.conf`
  - Expose port 80

- [ ] **U7.2** `wiremind-ui`: Create `nginx.conf`
  - Serve `dist/` as document root
  - `try_files $uri $uri/ /index.html` — enables React Router deep links
  - `location /api/ { proxy_pass http://forensics:8765/; }` — strip prefix via trailing slash
  - Proxy headers: `Host`, `X-Real-IP`, `X-Forwarded-For`
  - Gzip: `js`, `css`, `html`, `svg`

- [ ] **U7.3** `wiremind-ui`: Create `.dockerignore`
  - Ignore: `node_modules/`, `dist/`, `.env*`, `.git/`, `*.md`

- [ ] **U7.4** `wiremind-ui`: Verify API client base URL
  - Confirm `src/api/client.ts` uses `/api` (relative) — not hard-coded `localhost:8765`
  - Both Vite proxy (dev) and nginx proxy (Docker) route `/api/*` to the backend — no env var needed

- [x] **U7.5** `wiremind`: Add `wiremind-ui` service to `docker-compose.yaml`
  ```yaml
  wiremind-ui:
    build:
      context: ../wiremind-ui
      dockerfile: Dockerfile
    ports:
      - "3001:80"
    depends_on:
      forensics:
        condition: service_started
  ```

- [x] **U7.6** `wiremind`: Add `docker-compose.override.yaml` for local dev
  - Override `forensics` to expose port `8765` to the host so `npm run dev` Vite proxy still works
  - Keeps main `docker-compose.yaml` clean (no host-exposed backend port in prod-like mode)

- [x] **U7.7** Smoke test (updated with local paths)
  - [x] `docker compose build wiremind-ui` — build succeeds (context path updated in override)
  - [ ] `docker compose up forensics postgres redis wiremind-ui`
  - [x] `http://localhost:3001` — UI loads, no blank screen
  - [/] Navigate to Flows page — fix applied to API calling issue
  - [x] Navigate to ICMP page — fix applied to ICMP API calling issue
  - [ ] No CORS errors in browser DevTools console
  - [ ] Direct URL to `/threats` works (React Router deep link via nginx fallback)
  - [ ] `docker compose down` — clean shutdown

**Deliverable:** `docker compose up` → full stack at `localhost:3001`. No manual steps.

---

## IDE Setup (WebStorm)

1. Open `wiremind-ui/` as the project root in WebStorm
2. WebStorm auto-detects Vite + TypeScript — no extra config needed
3. Enable **Tailwind CSS plugin** (Settings → Plugins → "Tailwind CSS")
4. Enable **Prettier** for formatting (Settings → Languages → JavaScript → Prettier)
5. Add a **Run configuration**: `npm run dev` — starts the Vite dev server
6. Add a second **Run configuration**: `npm run generate:api` — regenerates types from spec

**Monorepo workspace tip:** In WebStorm, use *File → Open* on the parent directory
(`GolandProjects/`). Then right-click `wiremind-ui/` and "Attach" — you get both
repos in one window, GoLand for Go and WebStorm for the frontend.

---

## API Codegen Workflow

Whenever `docs/openapi.yaml` changes in the Go repo:

```bash
# from wiremind-ui/
npm run generate:api
# runs: openapi-typescript ../wiremind/docs/openapi.yaml -o src/api/schema.d.ts
```

Then fix any TypeScript errors — they're your spec-contract breakage report.

Add to `package.json`:

```json
{
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "generate:api": "openapi-typescript ../wiremind/docs/openapi.yaml -o src/api/schema.d.ts"
  }
}
```

---

## Prioritised Build Order

```
Phase 1  Scaffold + CORS fix        ✅ done
Phase 2  Core tables                ✅ done
Phase 3  Job management + SSE       → closes the submit→watch→query loop
Phase 4  Dashboard                  → overview, polish
Phase 5  Network graph              → high-value differentiator
Phase 6  Config & control           → IOC management, live capture
Phase 7  Docker integration         → one-command full stack deploy
```

Phases 5 and 6 can be parallelised once Phase 3 is done.
Phase 7 can be done any time after Phase 2 — it's infrastructure, not features.

---

## What to check at each phase end

| Phase | Smoke test |
|---|---|
| 1 ✅ | `npm run dev` → app loads. `/health` returns 200 in browser network tab. No CORS errors |
| 2 ✅ | All six table pages load with live data. Filtering by `src_ip` narrows rows correctly |
| 3 | Submit a PCAP path → status transitions `pending → processing → completed` in real time |
| 4 | Dashboard stats match values from `curl /api/v1/stats` |
| 5 | Graph renders for a parsed PCAP with >10 flows. Malicious node is red |
| 6 | Add IOC → appears in Go server's in-memory matcher (verify via `/api/v1/config/ioc`) |
| 7 | `docker compose up` → UI at `localhost:3001`, live data, no CORS errors, deep links work |
