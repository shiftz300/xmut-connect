"use strict";

const get = (id) => document.getElementById(id);
const set = (id, value) => { get(id).textContent = value; };
const states = {
  disconnected: "未连接", authenticating: "认证中", waiting_sms: "等待短信",
  connecting: "正在建立隧道", connected: "已连接", reconnecting: "正在恢复",
  expired: "会话已过期", error: "连接失败"
};
const problems = {
  unauthorized: "管理令牌无效。",
  connection_failed: "VPN 认证或连接失败，请检查配置后重试。",
  sms_timeout: "等待短信验证码超时，请重新登录。",
  sms_rejected: "网关未接受验证码，请重新登录。",
  stale_challenge: "这次验证码请求已结束或已提交。",
  unsupported_challenge: "网关要求当前页面无法处理的认证方式。",
  session_expired: "VPN 会话已过期。",
  dns_failure: "校园资源域名解析失败。",
  network_failure: "校园资源暂时不可达。",
  tunnel_interrupted: "隧道已中断，正在尝试恢复。",
  health_target_not_allowed: "健康检查地址未匹配 VPN 资源。",
  health_unexpected_response: "校园资源返回了非预期 HTTP 状态。",
  gateway_logout_unconfirmed: "本地连接已关闭，网关注销结果未确认。",
  state_conflict: "当前状态已变化，请刷新后操作。",
  login_rate_limited: "登录请求过于频繁，请稍后重试。",
  request_rate_limited: "请求过于频繁，请稍后重试。",
  invalid_sms_code: "验证码应为数字。",
  request_failed: "管理服务暂时无法访问。"
};
const dates = new Intl.DateTimeFormat("zh-CN", {dateStyle: "short", timeStyle: "medium"});
const clocks = new Intl.DateTimeFormat("zh-CN", {timeStyle: "medium"});
let token = "";
let current = null;
let poll = null;
let revision = 0;
let busy = false;
let lastLog = "";

function message(code) {
  set("notice", problems[code] || problems.request_failed);
  get("notice").hidden = false;
}

function clearAccess() {
  revision++;
  clearTimeout(poll);
  token = "";
  current = null;
  busy = false;
  lastLog = "";
  get("token").value = "";
  get("code").value = "";
  get("dashboard").hidden = true;
  get("access").hidden = false;
  get("logs").replaceChildren();
  get("notice").hidden = true;
}

async function api(path, body) {
  const headers = {Authorization: "Bearer " + token};
  const options = {headers, cache: "no-store", signal: AbortSignal.timeout(7000)};
  if (body !== undefined) {
    options.method = "POST";
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  try {
    const response = await fetch("/api/" + path, options);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "request_failed");
    return data;
  } catch (error) {
    throw new Error(Object.hasOwn(problems, error.message) ? error.message : "request_failed");
  }
}

function date(value) {
  return value ? dates.format(new Date(value)) : "—";
}

function render(status) {
  if (current?.challenge_id !== status.challenge_id) get("code").value = "";
  current = status;
  const waiting = status.state === "waiting_sms" && Boolean(status.challenge_id) && !status.stopping;
  const active = status.active;
  get("dashboard").hidden = false;
  get("access").hidden = true;
  get("state").dataset.state = status.state;
  set("state", status.stopping ? "正在停止" : (states[status.state] || "未知"));
  set("server", status.server);
  set("version", status.version);
  set("ip", status.virtual_ip || "—");
  set("auth-time", date(status.last_auth));
  set("health-time", date(status.health.last_success));
  const health = {healthy: "可达", pending: "检查中", idle: "待连接", disabled: "已关闭"};
  set("health", health[status.health.status] || "不可达");
  set("duration", status.connected_since ?
    `${Math.floor(status.connected_seconds / 3600)} 小时 ${Math.floor(status.connected_seconds / 60) % 60} 分 ${status.connected_seconds % 60} 秒` : "—");
  set("ss", status.services.shadowsocks ? "监听中" : "未运行");
  set("socks", status.services.socks5 ? "监听中" : "未运行");
  get("sms").hidden = !waiting;
  if (waiting) set("expires", `${clocks.format(new Date(status.challenge_expires))} 前有效`);
  get("sms").querySelector("button").disabled = busy || !waiting;
  set("auth-error", problems[status.error] || "");
  get("auth-error").hidden = !status.error;
  get("login").disabled = busy || active || status.stopping;
  get("reconnect").disabled = busy || Boolean(status.attempt_id) || status.stopping;
  get("cancel").disabled = busy || !status.attempt_id || status.stopping;
  get("logout").disabled = busy || !active || status.stopping;
}

function renderLogs(entries) {
  const fingerprint = JSON.stringify(entries);
  if (lastLog === fingerprint) return;
  lastLog = fingerprint;
  const list = get("logs");
  get("log-empty").hidden = entries.length > 0;
  if (list.childNodes.length === 0 && entries.length > 0) list.scrollTop = 0;
  const nearBottom = list.scrollTop + list.clientHeight + 24 >= list.scrollHeight;
  list.replaceChildren(...entries.map((entry) => {
    const row = document.createElement("li");
    const time = document.createElement("time");
    time.dateTime = entry.time;
    time.textContent = clocks.format(new Date(entry.time));
    const level = document.createElement("span");
    level.className = entry.level.toLowerCase();
    level.textContent = entry.level;
    const content = document.createElement("span");
    content.textContent = entry.message;
    row.append(time, level, content);
    return row;
  }));
  if (nearBottom) list.scrollTop = list.scrollHeight;
}

async function refresh(expected) {
  if (expected !== revision || !token) return;
  try {
    const [status, entries] = await Promise.all([api("status"), api("logs")]);
    if (expected !== revision) return;
    render(status);
    renderLogs(entries);
  } catch (error) {
    if (expected !== revision) return;
    if (error.message === "unauthorized") clearAccess();
    message(error.message);
  } finally {
    if (expected === revision && token) poll = setTimeout(() => refresh(expected), 2500);
  }
}

async function action(path, body = {}) {
  if (busy) return;
  busy = true;
  render(current);
  get("notice").hidden = true;
  clearTimeout(poll);
  const expected = ++revision;
  try {
    await api(path, body);
  } catch (error) {
    if (expected === revision) message(error.message);
  } finally {
    if (expected === revision) {
      busy = false;
      refresh(expected);
    }
  }
}

get("access").addEventListener("submit", (event) => {
  event.preventDefault();
  clearTimeout(poll);
  token = get("token").value.trim();
  get("token").value = "";
  get("notice").hidden = true;
  refresh(++revision);
});
for (const name of ["login", "reconnect", "logout"]) get(name).addEventListener("click", () => action(name));
get("cancel").addEventListener("click", () => action("cancel", {attempt_id: current.attempt_id}));
get("sms").addEventListener("submit", (event) => {
  event.preventDefault();
  const code = get("code").value;
  get("code").value = "";
  action("sms", {challenge_id: current.challenge_id, code});
});
