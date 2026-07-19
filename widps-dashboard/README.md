# WIDPS AI Dashboard

Frontend dashboard for the AI-based Wireless Intrusion Detection & Prevention System.
React + TypeScript + Tailwind v4 + Recharts + Framer Motion + Lucide icons.

## Run it

```bash
npm install
npm run dev
```

Opens at `http://localhost:5173`. All data is mocked/simulated for now (see below).

## Build

```bash
npm run build     # type-checks with tsc -b, then bundles with vite
npm run preview   # serve the production build locally
```

## Project structure

```
src/
├── main.tsx                  # entry point
├── App.tsx                   # page router, sidebar/topbar/feed shell
├── index.css                 # Tailwind v4 theme tokens (colors, fonts)
├── types/index.ts             # data contracts — keep in sync with Rust serde structs
├── data/mockData.ts           # realistic mock data for every page
├── hooks/useMockLiveData.ts   # simulated live updates — THE Tauri integration seam
├── components/
│   ├── common/                 # Card, StatCard, StatusBadge, AnimatedNumber, CircularProgress
│   └── layout/                  # Sidebar, TopBar, LiveAttackFeed, AlertCenter, ThreatLevelIndicator
└── pages/                      # one file per sidebar page
```

## Wiring to the Rust backend (Tauri)

Everything currently comes from `src/hooks/useMockLiveData.ts`, which uses `setInterval`
to fake live updates. To connect the real WIDPS Rust backend:

1. Wrap the project with Tauri (`cargo tauri init` inside this folder) and point its
   `distDir` at `dist/` (the Vite build output).

2. In your Rust WIDPS process, emit events matching the shapes in `src/types/index.ts`:

```rust
// example: after updating system stats
app_handle.emit_all("system-status", SystemStatus {
    monitoring_active: true,
    interface_name: "wlan1mon".into(),
    current_channel: current_channel.load(Ordering::Relaxed),
    // ... match field-for-field with SystemStatus in types/index.ts
}).unwrap();
```

   Use `#[derive(Serialize)]` with `#[serde(rename_all = "camelCase")]` on your Rust
   structs so the JSON keys match the camelCase TypeScript interfaces exactly.

3. Replace the body of each hook in `useMockLiveData.ts` with a `listen()` call:

```ts
import { listen } from '@tauri-apps/api/event';

export function useSystemStatus(): SystemStatus {
  const [status, setStatus] = useState<SystemStatus>(initialStatus);
  useEffect(() => {
    const unlisten = listen<SystemStatus>('system-status', (e) => setStatus(e.payload));
    return () => { unlisten.then((f) => f()); };
  }, []);
  return status;
}
```

   No page component needs to change — they all consume the hooks, not the mock data
   directly.

4. For one-off actions (Investigate/Block buttons in Threat Map, report generation in
   Reports), use `invoke()` instead of events:

```ts
import { invoke } from '@tauri-apps/api/core';
await invoke('block_device', { mac: attackerMac });
```

   and expose a matching `#[tauri::command] fn block_device(mac: String)` in Rust.

## Notes for your demo/report

- The color system, page structure, and status badges follow the spec exactly
  (background `#0B1220`, card `#111827`, accent blue/green/warning/danger as given).
- Numeric/data fields use a monospace font (JetBrains Mono) — a deliberate nod to
  real SOC tooling (Splunk, Kibana, Grafana all do this) so metrics read as
  operational data rather than UI copy.
- `prefers-reduced-motion` is respected globally.
- CSV/JSON export on the Event Log and Reports pages works client-side right now
  (downloads mock data) — swap the export functions to pull from live state once
  connected.
