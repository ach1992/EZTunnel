// Render the real Tunnel component against a synthetic provider. No backend,
// authentication, network credentials or production data are used by this fixture.
// Run Vite and open /tests/tun-probe.html?lang=en (or fa); #result reports PASS/FAIL.
import { mount, tick, unmount } from "svelte";
import Tunnel from "../src/pages/Tunnel.svelte";
import { live } from "../src/lib/live.svelte.js";
import { fleet } from "../src/lib/servers.svelte.js";
import { setLang, t } from "../src/lib/i18n.svelte.js";
import "../src/app.css";

const result = document.querySelector("#result");
const requests = [];
const checks = [];
const pair = "0123456789abcdef";
const makeTun = (name, address, peer_address) => ({ interface: name, address, peer_address,
  mtu: 1400, forwarding_port: null, interface_ready: true });
const makeEnd = (side, name, tun) => ({ side, name, tun, pair, state: "running",
  direction: "reverse", transport: "tcp", link: "listen :7000", down_bps: 0, up_bps: 0,
  uptime_sec: 120, link_state: "connected" });
let local = makeEnd("iran", "fixture", makeTun("ez0", "10.88.0.1", "10.88.0.2"));
let remote = makeEnd("foreign", "fixture", makeTun("ez1", "10.88.0.2", "10.88.0.1"));
let remoteId = "fixture-remote";
let online = true;

function snapshot() {
  live.snapshot = { at: Date.now(), tunnels: [structuredClone(local)] };
  fleet.list = [{ id: remoteId, name: "Fixture peer", online,
    snapshot: { tunnels: [structuredClone(remote)] } }];
}
function assert(value, message) {
  if (!value) throw new Error(message);
}
async function eventually(condition, message) {
  for (let n = 0; n < 100; n++) {
    if (condition()) return;
    await new Promise(resolve => setTimeout(resolve, 10));
    await tick();
  }
  throw new Error(message);
}
const panel = () => document.querySelector('[aria-labelledby="tp-tun"]');
const button = () => panel()?.querySelector("button");
const rows = () => panel()?.querySelector('[aria-live="polite"]');
const successes = () => Array.from(rows()?.querySelectorAll("span") ?? [])
  .filter(el => el.textContent === t("tunProbeOk")).length;
const answer = (request, target = request.target) => request.resolve(Response.json({
  target, attempted: true, interface_ready: true, reachable: true, peer: request.target.peer_address,
  detail: "synthetic peer reply"
}));
window.fetch = async (input, options) => {
  const path = new URL(input, location.origin).pathname;
  if (path.endsWith("/tools/tun_probe")) {
    const target = JSON.parse(options.body).expect_tun;
    return new Promise(resolve => requests.push({ path, target, resolve }));
  }
  if (path.endsWith("/status")) return Response.json({});
  if (path === "/api/history") return Response.json({ bucket_sec: 3600, tunnels: {} });
  throw new Error("Unexpected fixture API: " + path);
};
async function startProbe() {
  await eventually(() => button() && !button().disabled, "probe button not available");
  const before = requests.length;
  button().click();
  await eventually(() => requests.length === before + (online ? 2 : 1), "probe requests not sent");
  return requests.slice(before);
}
async function completedProbe() {
  const pending = await startProbe();
  for (const request of pending) answer(request);
  await eventually(() => successes() === pending.length && !button().disabled, "probe results not rendered");
  return pending;
}
async function clearAfterChange(label) {
  snapshot();
  await tick();
  await eventually(() => !rows(), "old results remained: " + label);
  checks.push(label);
}

try {
  setLang(new URLSearchParams(location.search).get("lang") === "fa" ? "fa" : "en");
  snapshot();
  const instance = mount(Tunnel, { target: document.querySelector("#fixture"), props: { name: local.name } });
  const first = await completedProbe();
  assert(first[0].target.address === local.tun.address && first[1].target.address === remote.tun.address,
    "probe requests are not bound to both displayed endpoints");
  checks.push("both effective targets sent and rendered");
  for (let n = 0; n < 5; n++) {
    local.down_bps += 100;
    local.tun.interface_ready = n % 2 === 0;
    remote.up_bps += 50;
    snapshot();
    await tick();
    assert(successes() === 2, "equivalent snapshots reset results");
  }
  checks.push("five equivalent snapshots preserve completed results");
  local.tun.address = "10.88.1.1";
  local.tun.peer_address = "10.88.1.2";
  remote.tun.address = local.tun.peer_address;
  remote.tun.peer_address = local.tun.address;
  await clearAfterChange("same pair, changed IPs invalidate results");
  await completedProbe();
  local.tun.interface = "ez2";
  await clearAfterChange("changed local interface invalidates results");
  await completedProbe();
  remote.tun.interface = "ez3";
  await clearAfterChange("changed remote interface invalidates results");
  await completedProbe();
  remoteId = "fixture-remote-replacement";
  await clearAfterChange("changed matched endpoint invalidates results");
  await completedProbe();
  local.tun.mtu = 1320;
  await clearAfterChange("changed MTU invalidates results");
  await completedProbe();
  const savedTun = local.tun;
  local.tun = null;
  await clearAfterChange("removed TUN clears results");
  local.tun = savedTun;
  await clearAfterChange("restoring TUN does not resurrect results");
  const outstanding = await startProbe();
  local.tun.interface = "ez4";
  await clearAfterChange("changed in-flight target clears pending results");
  for (const request of outstanding) answer(request);
  await eventually(() => !button().disabled, "old requests did not finish");
  assert(!rows(), "late replies populated a different target");
  checks.push("late replies cannot repopulate new target");
  const stale = await startProbe();
  for (const request of stale) answer(request, { ...request.target, address: "10.99.0.1" });
  await eventually(() => rows()?.textContent.includes(t("tunProbeChanged")) && !button().disabled,
    "mismatched reply did not report a target error");
  assert(successes() === 0, "mismatched reply reported success");
  checks.push("mismatched response cannot report success");
  const unbound = await startProbe();
  for (const request of unbound) answer(request, null);
  await eventually(() => rows()?.textContent.includes(t("tunProbeChanged")) && !button().disabled,
    "unbound reply did not report a target error");
  assert(successes() === 0, "unbound reply reported success");
  checks.push("unbound response cannot report success");
  await completedProbe();
  online = false;
  snapshot();
  await tick();
  assert(successes() === 2, "online state reset historical results");
  checks.push("peer availability alone preserves completed result");
  await completedProbe();
  assert(successes() === 1, "offline peer was probed");
  checks.push("offline peer is not probed");
  await unmount(instance);
  result.textContent = checks.map(check => "PASS " + check).join("\n");
  result.dataset.status = "passed";
} catch (error) {
  result.textContent = checks.map(check => "PASS " + check).concat("FAIL " + error.stack).join("\n");
  result.dataset.status = "failed";
}
