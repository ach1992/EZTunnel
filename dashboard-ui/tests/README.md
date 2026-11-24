# TUN probe rendering regression

Run `npm ci` and `npm run dev -- --host 127.0.0.1` from `dashboard-ui`.
Open `http://127.0.0.1:5173/tests/tun-probe.html?lang=en` (or `lang=fa`).
The fixture renders the actual Tunnel component with synthetic snapshots and
controlled API replies. It reports individual assertions and a final
`#result[data-status=passed]` or `#result[data-status=failed]`.
It does not connect to a Dashboard, require authentication, or enter the
production bundle. Use a desktop viewport for English and a mobile viewport
for Persian to exercise both layouts.
