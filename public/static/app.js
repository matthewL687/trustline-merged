/* Trustline frontend: the five layers, filled in from the scan's event stream.
   Report text comes from scanned code and from the model, so it only ever
   reaches the page through textContent. Nothing on this page is mocked. */
(function () {
  "use strict";

  var POLL_EVERY_MS = 1500;
  var POLL_LIMIT = 240; // about six minutes before offering to keep waiting
  var TABLE_ROWS = 14;

  var SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  var SEV_LABEL = { critical: "critical", high: "high", medium: "medium", low: "low", info: "safe" };
  var KIND_LABEL = { repo: "GitHub repo", website: "website", path: "local folder" };
  var TYPE_LABEL = { script: "Script", api: "API endpoint", asset: "Static asset", bucket: "Storage bucket", docs_link: "Docs link", other: "Other" };
  var RUNS_LABEL = { browser: "Every visitor’s browser", server: "Your servers", build: "Build", deploy: "Deploy / infra", ci: "CI", test: "Tests only", docs_only: "Docs only" };
  var ASIDE_LABEL = {
    allowlisted: ["well-known host", "well-known hosts"],
    reserved_domain: ["reserved example domain", "reserved example domains"],
    reserved_tld: ["reserved test TLD", "reserved test TLDs"],
    ip_address: ["IP literal", "IP literals"],
    placeholder: ["template placeholder", "template placeholders"],
    no_public_suffix: ["name without a public suffix", "names without a public suffix"]
  };
  var PROVIDER = { s3: "S3", gcs: "GCS", azure: "Azure Blob" };
  var WAITING = {
    1: "Waiting for a target.",
    2: "Waiting for Layer 01.",
    3: "Waiting for Layer 02.",
    4: "Waiting for Layer 03.",
    5: "Waiting for Layer 04."
  };
  var ENGINE = {
    1: "code · file walk + patterns",
    2: "Muse Spark 1.3",
    3: "code lookups + Muse Spark agent",
    4: "Muse Spark 1.3 + code rules",
    5: "code · ranked list"
  };
  var DEMO_ENGINE = {
    2: "scripted stand-in for Muse Spark",
    3: "stubbed lookups + scripted agent",
    4: "scripted stand-in + code rules"
  };
  // Each layer shows its result; details open on request and stay open across
  // live updates and later scans.
  var OPEN = { 1: false, 2: false, 3: false, 4: false, 5: false };

  /* ---------- DOM helpers (textContent only) ---------- */

  function $(selector, root) { return (root || document).querySelector(selector); }
  function $$(selector, root) { return Array.prototype.slice.call((root || document).querySelectorAll(selector)); }

  function h(tag, props) {
    var node = document.createElement(tag);
    if (props) {
      Object.keys(props).forEach(function (key) {
        var value = props[key];
        if (value == null || value === false) { return; }
        if (key === "class") { node.className = value; }
        else if (key === "text") { node.textContent = String(value); }
        else if (key.slice(0, 2) === "on") { node.addEventListener(key.slice(2), value); }
        else { node.setAttribute(key, value === true ? "" : String(value)); }
      });
    }
    add(node, Array.prototype.slice.call(arguments, 2));
    return node;
  }

  function add(node, kids) {
    kids.forEach(function (kid) {
      if (Array.isArray(kid)) { add(node, kid); return; }
      if (kid == null || kid === false || kid === "") { return; }
      node.appendChild(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    });
    return node;
  }

  function fmt(n) { return Number(n || 0).toLocaleString("en-US"); }
  function pad(n) { return String(n).padStart(2, "0"); }
  function plural(n, one, many) { return n === 1 ? one : (many || one + "s"); }
  function secs(s) { return s < 10 ? s.toFixed(1) + "s" : Math.round(s) + "s"; }
  function clock(ms) {
    var total = Math.max(0, Math.floor(ms / 1000));
    return Math.floor(total / 60) + ":" + String(total % 60).padStart(2, "0");
  }
  function money(x) { return "$" + (x < 0.01 ? x.toFixed(4) : x.toFixed(2)); }
  function unique(list) { return list.filter(function (item, i) { return list.indexOf(item) === i; }); }
  function scanQuery(id) { return "?scan=" + encodeURIComponent(id); }

  /* ---------- state ---------- */

  var S = fresh();
  var dirty = {};
  var queued = false;
  var timer = null;

  function fresh() {
    return {
      mode: "idle",        // live | demo | shared
      scanId: "",
      kind: "",
      target: "",
      recordedWith: "",
      layers: {},
      gather: null,
      classified: null,
      pre: {},             // target -> { kind, refs, next, hard, evidence }
      turns: {},           // target -> [{ tool, args, result, alert }]
      order: [],
      calls: 0,
      classifying: null,
      ranked: {},          // target -> finding
      done: null,
      report: null,
      failed: "",
      notices: [],
      source: null,
      abort: null,         // cancels the one-request live scan stream
      shareable: true,     // false on serverless hosts: another instance can't replay the job
      pollTimer: null,
      streamed: false,
      finished: false,
      fromReport: false,
      startedTs: null,
      doneTs: null,
      clientStart: Date.now()
    };
  }

  function layer(n) {
    if (!S.layers[n]) { S.layers[n] = { state: "pending", t0: null, t1: null }; }
    return S.layers[n];
  }
  function begin(n, ts) {
    var l = layer(n);
    if (l.state === "pending") { l.state = "running"; l.t0 = ts; }
  }
  function finish(n, ts) {
    var l = layer(n);
    if (l.state === "done") { return; }
    if (l.t0 == null) { l.t0 = ts; }
    l.state = "done";
    l.t1 = ts;
  }
  // A target's references add up to its strongest step; an older recording
  // sent one per reference, so the last one is not always the target's.
  var STEP_ORDER = ["agent", "facts", "popular", "low_exposure"];
  function strongerStep(a, b) {
    if (!a) { return b; }
    if (!b) { return a; }
    var ia = STEP_ORDER.indexOf(a), ib = STEP_ORDER.indexOf(b);
    if (ia === -1) { return b; }
    if (ib === -1) { return a; }
    return ia <= ib ? a : b;
  }

  function noteTarget(name) {
    var key = String(name || "");
    if (key && S.order.indexOf(key) === -1) { S.order.push(key); }
    return key;
  }

  function mark() {
    var list = arguments.length ? Array.prototype.slice.call(arguments) : [1, 2, 3, 4, 5];
    list.forEach(function (n) { dirty[n] = true; });
    if (queued) { return; }
    queued = true;
    requestAnimationFrame(function () {
      queued = false;
      renderChrome();
      Object.keys(dirty).forEach(function (n) { renderLayer(Number(n)); });
      dirty = {};
    });
  }

  /* ---------- the event stream ---------- */

  function consume(ev) {
    var ts = typeof ev.ts === "number" ? ev.ts : Date.now() / 1000;
    var key;
    switch (ev.type) {
      case "started":
        S.kind = ev.kind || S.kind;
        S.target = ev.target || S.target;
        S.recordedWith = ev.recorded_with || S.recordedWith;
        if (ev.model_calls_enabled === false) {
          S.notices.push("Free scan mode: no Meta API calls will be made.");
        }
        S.startedTs = ts;
        begin(1, ts);
        mark(1);
        break;
      case "extracted":
        S.gather = ev;
        (ev.targets || []).forEach(function (row) { noteTarget(row.target); });
        finish(1, ts);
        begin(2, ts);
        mark(1, 2);
        break;
      case "classified":
        S.classified = ev;
        (ev.items || []).forEach(function (item) { noteTarget(item.target); });
        finish(1, ts);
        finish(2, ts);
        begin(3, ts);
        mark(2, 3);
        break;
      case "classifying":
        S.classifying = ev;
        mark(2);
        break;
      case "precheck":
        finish(1, ts);
        finish(2, ts);
        begin(3, ts);
        key = noteTarget(ev.target);
        var row = S.pre[key] || { refs: 0 };
        row.refs += 1;
        row.kind = ev.kind || row.kind;
        row.hard = row.hard || !!ev.hard_signal;
        row.next = strongerStep(row.next, ev.next);
        if (ev.evidence) { row.evidence = ev.evidence; }
        if (ev.flags) { row.flags = ev.flags; }
        if (ev.max_turns) { row.maxTurns = ev.max_turns; }
        S.pre[key] = row;
        mark(2, 3);
        break;
      case "checked":
        // history from code (crt.sh, Wayback) for a target without a red flag
        key = noteTarget(ev.target);
        if (S.pre[key] && ev.evidence) { S.pre[key].evidence = ev.evidence; }
        mark(3);
        break;
      case "plan":
      case "act":
      case "observe":
        finish(1, ts);
        finish(2, ts);
        begin(3, ts);
        agentStep(ev);
        mark(3);
        break;
      case "ranked":
        finish(1, ts);
        finish(2, ts);
        finish(3, ts);
        begin(4, ts);
        key = noteTarget(ev.target);
        S.ranked[key] = ev;
        mark(3, 4);
        break;
      case "done":
        [1, 2, 3, 4, 5].forEach(function (n) { finish(n, ts); });
        S.done = ev;
        S.doneTs = ts;
        S.finished = true;
        mark();
        break;
      case "notice":
        if (ev.message) { S.notices.push(String(ev.message)); }
        mark();
        break;
      case "error":
        S.failed = String(ev.message || "The scan failed.");
        [1, 2, 3, 4, 5].forEach(function (n) {
          if (layer(n).state === "running") { layer(n).state = "error"; }
        });
        mark();
        break;
    }
  }

  // plan names the tool Muse Spark picked; observe carries what the tool returned.
  function agentStep(ev) {
    var key = noteTarget(ev.target);
    var list = S.turns[key] || (S.turns[key] = []);
    if (ev.type === "plan") {
      if (ev.tool !== "done") { S.calls += 1; }
      list.push({ tool: String(ev.tool || ""), args: ev.args || {}, result: null, alert: false });
      return;
    }
    if (ev.type !== "observe") { return; }
    var open = null;
    for (var i = list.length - 1; i >= 0; i -= 1) {
      if (list[i].result == null && list[i].tool === ev.tool) { open = list[i]; break; }
    }
    if (!open) { return; }
    var read = readResult(ev.result_summary);
    open.result = read.text;
    open.alert = read.alert;
  }

  // A short line from the tool's own result fields. No model text, no guessing.
  function readResult(raw) {
    var data = null;
    try { data = JSON.parse(String(raw)); } catch (err) { data = null; }
    if (!data || typeof data !== "object") {
      return { text: String(raw == null ? "" : raw).slice(0, 90), alert: false };
    }
    if (data.done === true) { return { text: String(data.summary || "enough evidence"), alert: false }; }
    if (data.error) { return { text: "refused: " + String(data.error).slice(0, 80), alert: false }; }
    var parts = [];
    if (typeof data.status === "string" && data.status) { parts.push(data.status); }
    else if (typeof data.exists === "boolean") { parts.push(data.exists ? "exists" : "not found"); }
    if (typeof data.http_status === "number") { parts.push("HTTP " + data.http_status); }
    if (typeof data.days_to_expiry === "number") { parts.push(data.days_to_expiry + " days to expiry"); }
    if (data.first_snapshot) { parts.push("archived since " + String(data.first_snapshot).slice(0, 4)); }
    if (data.first_seen) { parts.push("certs since " + String(data.first_seen).slice(0, 4)); }
    if (data.parked) { parts.push("parked"); }
    if (data.for_sale) { parts.push("for sale"); }
    var text = parts.join(" · ") || String(raw).slice(0, 90);
    return { text: text, alert: /unregistered|nxdomain|nosuchbucket|not found|missing|unclaimed|parked|for sale/i.test(text) };
  }

  /* ---------- facts: evidence fields to plain lines ---------- */

  function facts(evidence) {
    var e = evidence || {};
    var out = [];
    var bucket = e.bucket_probe;
    if (bucket) {
      var provider = (PROVIDER[bucket.provider] || bucket.provider || "storage") + " bucket";
      if (bucket.status === "NoSuchBucket") { out.push(["alert", provider, "does not exist; anyone can create it"]); }
      else if (bucket.status === "exists") { out.push(["ok", provider, "exists" + (bucket.http_status ? " (HTTP " + bucket.http_status + ")" : "")]); }
      else { out.push(["unknown", provider, String(bucket.status || "no answer")]); }
    }
    var dns = e.dns;
    if (dns) {
      var dnsStatus = String(dns.status || "").toLowerCase();
      if (dnsStatus === "nxdomain") { out.push(["alert", "DNS", "does not resolve (NXDOMAIN)"]); }
      else if (dnsStatus === "resolves") {
        var via = (dns.cnames || []).slice(0, 2).join(", ");
        out.push(["ok", "DNS", "resolves" + (via ? " via " + via : "")]);
      } else { out.push(["unknown", "DNS", dnsStatus || "no answer"]); }
    }
    var rdap = e.rdap;
    if (rdap) {
      var rdapStatus = String(rdap.status || "").toLowerCase();
      var days = rdap.days_to_expiry;
      if (rdapStatus === "unregistered") { out.push(["alert", "RDAP", (rdap.domain || "the domain") + " is not registered"]); }
      else if (rdapStatus === "registered") {
        var line = "registered" + (rdap.registrar ? " with " + rdap.registrar : "");
        if (typeof days === "number") { line += ", expires in " + fmt(days) + " " + plural(days, "day"); }
        out.push([typeof days === "number" && days <= 90 ? "notice" : "ok", "RDAP", line]);
      } else { out.push(["unknown", "RDAP", rdapStatus || "no record"]); }
    }
    var platform = e.platform_takeover;
    if (platform && platform.status && platform.status !== "skipped") {
      var name = platform.platform || "Platform";
      if (platform.status === "unclaimed") { out.push(["alert", "Platform", name + " is unclaimed" + (platform.takeover ? " (" + platform.takeover + ")" : "")]); }
      else { out.push(["ok", "Platform", name + ": " + platform.status]); }
    }
    var owner = e.github_owner;
    if (owner) {
      var ownerStatus = String(owner.status || "").toLowerCase();
      var who = owner.owner ? "account " + owner.owner : "account";
      if (ownerStatus === "missing" || owner.exists === false) { out.push(["alert", "GitHub", who + " does not exist"]); }
      else if (ownerStatus === "exists" || owner.exists === true) { out.push(["ok", "GitHub", who + " exists"]); }
      else { out.push(["unknown", "GitHub", ownerStatus || "no answer"]); }
    }
    var repo = e.github_repo;
    if (repo) {
      var repoStatus = String(repo.status || "").toLowerCase();
      var what = repo.owner && repo.repo ? "repo " + repo.owner + "/" + repo.repo : "repo";
      if (repoStatus === "missing" || repo.exists === false) { out.push(["alert", "GitHub", what + " does not exist"]); }
      else if (repoStatus === "disabled") { out.push(["alert", "GitHub", what + " is disabled by GitHub"]); }
      else if (repoStatus === "exists" || repo.exists === true) { out.push(["ok", "GitHub", what + " exists"]); }
      else { out.push(["unknown", "GitHub", repoStatus || "no answer"]); }
    }
    var live = e.live_fetch;
    if (live && live.status) {
      if (live.for_sale) { out.push(["alert", "Live fetch", "listed for sale"]); }
      else if (live.parked) { out.push(["alert", "Live fetch", "parked page"]); }
      else { out.push(["info", "Live fetch", (live.http_status ? "HTTP " + live.http_status : live.status) + (live.title ? " · " + live.title : "")]); }
    }
    var certs = e.cert_history;
    if (certs && certs.status) {
      out.push(certs.first_seen
        ? ["info", "crt.sh", "certificates from " + certs.first_seen + " to " + (certs.last_seen || "now")]
        : ["unknown", "crt.sh", "no certificates returned"]);
    }
    var wayback = e.wayback;
    if (wayback && wayback.status) {
      out.push(wayback.first_snapshot
        ? ["info", "Wayback", "snapshots from " + snapshotDate(wayback.first_snapshot) + " to " + snapshotDate(wayback.last_snapshot)]
        : ["unknown", "Wayback", "no snapshots returned"]);
    }
    // a bucket's rank is its cloud provider's, which says nothing about the bucket
    if (typeof e.tranco_rank === "number" && !bucket) { out.push(["info", "Tranco", "rank " + fmt(e.tranco_rank) + " (popularity only)"]); }
    return out;
  }

  function snapshotDate(stamp) {
    var text = String(stamp || "");
    return /^\d{8}/.test(text) ? text.slice(0, 4) + "-" + text.slice(4, 6) + "-" + text.slice(6, 8) : text || "now";
  }

  function kindLabel(target, kind, evidence, platform) {
    if (kind === "bucket") { return "storage bucket"; }
    if (/^github\.com\/[^/]+\/[^/]+/.test(target)) { return "GitHub Action repo"; }
    if (/^github\.com\//.test(target)) { return "GitHub account"; }
    var found = platform || (evidence && evidence.platform_takeover && evidence.platform_takeover.platform);
    return found ? found + " host" : "domain";
  }

  /* ---------- small pieces ---------- */

  function wait(text) { return h("p", { class: "wait mono", text: text }); }
  function pending(text) { return h("p", { class: "pending", text: text }); }
  function tname(name, sub) { return h("div", { class: "tgt" }, name, sub ? h("small", { text: sub }) : null); }
  function stat(big, label) { return h("div", { class: "stat" }, h("b", { text: big }), h("span", { text: label })); }
  function sev(severity) { return h("span", { class: "sev sev-" + (SEV_LABEL[severity] ? severity : "low"), text: SEV_LABEL[severity] || severity }); }
  function meter(n) {
    return h("span", { class: "meter" + (n >= 3 ? " critical" : ""), "aria-hidden": "true" },
      [0, 1, 2].map(function (i) { return h("i", { class: i < n ? "on" : null }); }));
  }
  function fact(item) {
    return h("li", { class: "fact lvl-" + item[0] },
      h("i", { class: "sq", "aria-hidden": "true" }),
      h("span", { class: "src", text: item[1] }),
      h("span", { class: "val" }, h("span", { class: "sr", text: item[0] + ": " }), item[2]));
  }
  function more(key, summary, body) {
    return h("details", { class: "more", "data-key": key }, h("summary", { text: summary }), body);
  }
  function table(className, heads, rows) {
    return h("table", { class: className },
      h("thead", null, h("tr", null, heads.map(function (name) {
        return h("th", { class: name === "Refs" || name === "Files" ? "num-col" : null, text: name });
      }))),
      h("tbody", null, rows));
  }
  function whereList(finding) {
    return (finding.references || []).map(function (ref) {
      if (typeof ref === "string") { return ref; }
      if (!ref || typeof ref !== "object") { return ""; }
      var base = ref.page_url || ref.file || "";
      return base ? base + (ref.line ? ":" + ref.line : "") : "";
    }).filter(Boolean);
  }
  function whereText(finding) {
    var all = whereList(finding);
    return all.slice(0, 3).join(", ") + (all.length > 3 ? " +" + (all.length - 3) + " more" : "");
  }
  function evidenceKeys(finding) {
    var text = String(finding.evidence_line || "").replace(/^Evidence:\s*/, "");
    var parts = text ? text.split(" · ") : [];
    return parts.length ? h("div", { class: "keys", "aria-label": "Evidence used" },
      parts.map(function (part) { return h("span", { class: "key", text: part }); })) : null;
  }
  function findingsSorted() {
    var list = S.report && Array.isArray(S.report.findings)
      ? S.report.findings.slice()
      : Object.keys(S.ranked).map(function (key) { return S.ranked[key]; });
    return list.sort(function (a, b) {
      var left = SEV_ORDER[a.severity] == null ? 9 : SEV_ORDER[a.severity];
      var right = SEV_ORDER[b.severity] == null ? 9 : SEV_ORDER[b.severity];
      if (left !== right) { return left - right; }
      if ((b.blast_radius || 0) !== (a.blast_radius || 0)) { return (b.blast_radius || 0) - (a.blast_radius || 0); }
      return String(a.target).localeCompare(String(b.target));
    });
  }
  // scripts/record_demo.py marks a demo recorded with Muse Spark as "live"
  function scripted() { return S.mode === "demo" && S.recordedWith !== "live"; }

  /* ---------- layer 01: gather ---------- */

  function summaryGather() {
    var g = S.gather;
    if (!g) {
      if (S.fromReport) { return pending("Not part of the saved report. Run the scan again to see every reference."); }
      if (layer(1).state !== "running") { return null; }
      return pending(S.kind === "website"
        ? "Fetching the page and the scripts it loads…"
        : S.kind === "repo" ? "Downloading the repository and reading every text file…" : "Reading every text file…");
    }
    var cov = g.coverage || {};
    var site = S.kind === "website";
    var total = g.targets_total != null ? g.targets_total : (g.targets || []).length;
    return h("div", { class: "stats" },
      stat(fmt(cov.files_scanned), site ? plural(cov.files_scanned, "page") + " read" : cov.truncated ? "of " + fmt(cov.files_total) + " files read" : "files read"),
      stat(fmt(g.references), "outside references"),
      stat(fmt(total), "targets that could change hands"),
      stat(fmt(g.filtered), "set aside as inert"));
  }

  function renderGather() {
    var g = S.gather;
    if (!g) { return null; }
    var cov = g.coverage || {};
    var total = g.targets_total != null ? g.targets_total : (g.targets || []).length;
    var out = [];
    var rows = (g.targets || []).map(function (t) {
      var first = t.first || {};
      return h("tr", null,
        h("td", { "data-label": "Target" }, tname(t.target, kindLabel(t.target, t.kind, null, t.platform))),
        h("td", { "data-label": "First found" },
          h("span", { class: "loc", text: first.file + (first.line ? ":" + first.line : "") }),
          h("code", { class: "code", text: first.raw })),
        h("td", { "data-label": "Refs", class: "num-col", text: fmt(t.refs) }),
        h("td", { "data-label": "Files", class: "num-col", text: fmt(t.files) }));
    });
    var heads = ["Target", "First found", "Refs", "Files"];
    if (!rows.length) {
      out.push(h("p", { class: "mono", text: "No outside domains, buckets, or accounts that could change hands." }));
    } else {
      out.push(table("gat", heads, rows.slice(0, TABLE_ROWS)));
      if (rows.length > TABLE_ROWS) {
        out.push(more("g-more", (rows.length - TABLE_ROWS) + " more " + plural(rows.length - TABLE_ROWS, "target"), table("gat", heads, rows.slice(TABLE_ROWS))));
      }
      if (total > rows.length) { out.push(h("p", { class: "aside-line mono", text: "Showing the first " + fmt(rows.length) + " of " + fmt(total) + " targets." })); }
    }
    var aside = g.set_aside || {};
    var parts = Object.keys(aside).map(function (reason) {
      var item = aside[reason];
      var examples = (item.examples || []).slice(0, 3).join(", ");
      var label = ASIDE_LABEL[reason] || [reason.replace(/_/g, " "), reason.replace(/_/g, " ")];
      return fmt(item.count) + " " + label[item.count === 1 ? 0 : 1] + (examples ? " (" + examples + (item.count > 3 ? ", …" : "") + ")" : "");
    });
    if (parts.length) { out.push(h("p", { class: "aside-line mono" }, h("span", { class: "dim", text: "Set aside: " }), parts.join(" · "))); }
    if (cov.truncated) {
      out.push(h("p", { class: "aside-line mono", text: "Scan limit reached (" + String(cov.reason || "cap").replace(/_/g, " ") + "): " + fmt(cov.files_total - cov.files_scanned) + " files were not read." }));
    }
    return out;
  }

  /* ---------- layer 02: classify ---------- */

  function countBy(list, key) {
    var out = {};
    list.forEach(function (item) { out[item[key]] = (out[item[key]] || 0) + 1; });
    return out;
  }

  function summaryClassify() {
    var c = S.classified;
    if (!c) {
      if (S.fromReport) { return pending("Not part of the saved report."); }
      if (layer(2).state === "running") {
        var n = S.gather ? S.gather.actionable : 0;
        if (S.classifying && S.classifying.total) {
          return pending("Muse Spark classified " + fmt(S.classifying.completed) + " of " + fmt(S.classifying.total) + " grouped references…");
        }
        var targets = S.gather && S.gather.targets_total ? " across " + fmt(S.gather.targets_total) + " targets" : "";
        return pending("Grouping repeated references before classification: " + (n ? fmt(n) + " references" : "references") + targets + "…");
      }
      return layer(2).state === "done" ? pending("No classification details were sent.") : null;
    }
    var items = c.items || [];
    var total = c.total != null ? c.total : items.length;
    if (!total) { return h("p", { class: "mono", text: "Nothing to classify." }); }
    // counts over every reference; an older recording only has the listed ones
    var runs = c.runs_in || countBy(items, "runs_in");
    function count(keys) { return keys.reduce(function (sum, key) { return sum + (runs[key] || 0); }, 0); }
    return h("div", { class: "stats" },
      stat(fmt(total), plural(total, "reference") + " labeled"),
      stat(fmt(count(["browser"])), "load in a visitor’s browser"),
      stat(fmt(count(["server", "build", "deploy", "ci"])), "run on servers, builds or CI"),
      stat(fmt(count(["test", "docs_only"])), "only in tests or docs"));
  }

  function renderClassify() {
    var c = S.classified;
    if (!c) { return null; }
    var items = c.items || [];
    if (!items.length) { return null; }
    var groups = {};
    var keys = [];
    items.forEach(function (item) {
      if (!groups[item.target]) { groups[item.target] = []; keys.push(item.target); }
      groups[item.target].push(item);
    });
    var rows = keys.map(function (target) {
      var list = groups[target];
      var top = list.reduce(function (best, item) { return item.blast_radius > best.blast_radius ? item : best; }, list[0]);
      var runs = unique(list.map(function (item) { return RUNS_LABEL[item.runs_in] || item.runs_in; }));
      return h("tr", null,
        h("td", { "data-label": "Target" }, tname(target, fmt(list.length) + " " + plural(list.length, "reference"))),
        h("td", { "data-label": "What it is", text: TYPE_LABEL[top.type] || top.type }),
        h("td", { "data-label": "Runs in", text: runs.join(", ") }),
        h("td", { "data-label": "Blast radius" }, meter(top.blast_radius), String(top.blast_radius) + " of 3"),
        h("td", { "data-label": "Why" }, top.reason, h("span", { class: "heur", text: top.file + ":" + top.line + " · confidence " + Math.round((top.confidence || 0) * 100) + "%" })));
    });
    var heads = ["Target", "What it is", "Runs in", "Blast radius", "Why"];
    var out = [table("cls", heads, rows.slice(0, TABLE_ROWS))];
    if (rows.length > TABLE_ROWS) {
      out.push(more("c-more", (rows.length - TABLE_ROWS) + " more " + plural(rows.length - TABLE_ROWS, "target"), table("cls", heads, rows.slice(TABLE_ROWS))));
    }
    if (c.total > items.length) { out.push(h("p", { class: "aside-line mono", text: "Showing the first " + fmt(items.length) + " of " + fmt(c.total) + " references." })); }
    return out;
  }

  /* ---------- layer 03: investigate ---------- */

  function stepNote(key, pre, turns) {
    var budget = (S.done && S.done.budget_targets) || [];
    if (budget.indexOf(key) !== -1) { return "Agent skipped: the scan reached its agent budget; code lookup facts were kept."; }
    if (pre.next === "popular") { return "No agent needed: a top-ranked domain that resolves."; }
    if (pre.next === "facts") {
      // say only what code actually ran for this target
      var e = pre.evidence || {};
      var ran = [e.live_fetch ? "the live page" : "", e.cert_history || e.wayback ? "its history" : ""].filter(Boolean);
      return "No agent needed: no red flag." + (ran.length ? " Code also checked " + ran.join(" and ") + "." : "") + " Rank weighs these facts.";
    }
    if (pre.next === "low_exposure") { return "No agent needed: low exposure and no hard signal."; }
    if (pre.next === "agent" && !turns.length) {
      return layer(3).state === "running" ? "Queued for the agent…" : "Agent skipped: the scan’s time budget ran out. Rank used the facts above.";
    }
    return "";
  }

  function traceLine(turn, index) {
    var call = turn.tool === "done"
      ? [h("span", { class: "tool", text: "done" })]
      : [h("span", { class: "tool", text: turn.tool }), "(" + argText(turn.args) + ")"];
    return h("li", null,
      h("span", { class: "tn", text: pad(index + 1) }),
      h("span", null, call, " → ",
        h("span", { class: "res" + (turn.alert ? " alert" : ""), text: turn.result == null ? "running…" : turn.result })));
  }

  function argText(args) {
    var keys = Object.keys(args || {});
    if (!keys.length) { return ""; }
    var value = args[keys[0]];
    return JSON.stringify(typeof value === "string" ? value : String(value));
  }

  function investigated() {
    return S.order.filter(function (key) {
      return S.pre[key] || S.turns[key] || (S.fromReport && S.ranked[key]);
    });
  }

  function evidenceFor(key) {
    var finding = S.ranked[key];
    return (finding && finding.evidence) || (S.pre[key] || {}).evidence || {};
  }

  function summaryInvestigate() {
    var state = layer(3).state;
    var keys = investigated();
    if (!keys.length) {
      if (state === "running") { return pending("Looking up who owns each target now…"); }
      return state === "done" ? h("p", { class: "mono", text: "Nothing to look up." }) : null;
    }
    var agent = keys.filter(function (key) {
      var budget = (S.done && S.done.budget_targets) || [];
      return budget.indexOf(key) === -1 && ((S.pre[key] || {}).next === "agent" || (S.turns[key] || []).length);
    }).length;
    var flagged = keys.filter(function (key) {
      return facts(evidenceFor(key)).some(function (item) { return item[0] === "alert"; });
    }).length;
    return h("div", { class: "stats" },
      stat(fmt(keys.length), plural(keys.length, "target") + " checked"),
      stat(fmt(agent), "agent candidates"),
      stat(fmt(S.calls), "agent tool " + plural(S.calls, "call")),
      stat(fmt(flagged), "with a red flag"));
  }

  function renderInvestigate() {
    var keys = investigated();
    if (!keys.length) { return null; }
    var legend = h("div", { class: "legend", "aria-hidden": "true" },
      ["alert", "notice", "ok", "info"].map(function (level) {
        return h("span", null, h("i", { class: "sq sq-" + level }), level);
      }));
    var blocks = keys.map(function (key) {
      var pre = S.pre[key] || {};
      var finding = S.ranked[key];
      var evidence = evidenceFor(key);
      var list = facts(evidence);
      var turns = S.turns[key] || [];
      var kind = (finding && finding.kind) || pre.kind;
      var note = stepNote(key, pre, turns);
      return h("div", { class: "ev" },
        tname(key, kindLabel(key, kind, evidence) + (pre.refs > 1 ? " · " + pre.refs + " refs" : "")),
        h("div", null,
          list.length ? h("ul", { class: "facts" }, list.map(fact)) : pending("Checking…"),
          pre.next === "agent" && (pre.flags || []).length ? h("p", { class: "step", text: "Sent to the agent: " + pre.flags.join(", ") + "." }) : null,
          turns.length ? [
            h("p", { class: "step", text: (scripted() ? "Scripted agent" : "Muse Spark agent") + ", " + turns.length + " " + plural(turns.length, "step") + (pre.maxTurns ? " of " + pre.maxTurns : "") + ":" }),
            h("ol", { class: "trace" }, turns.map(traceLine))
          ] : null,
          note ? h("p", { class: "step", text: note }) : null));
    });
    return [legend].concat(blocks);
  }

  /* ---------- layer 04: reason ---------- */

  function raisedByRule(f) { return Boolean(f.floor_applied && f.model_severity && f.model_severity !== f.severity); }

  function summaryReason() {
    var list = findingsSorted();
    if (!list.length) {
      if (layer(4).state === "running") { return pending("Muse Spark is weighing exposure against the evidence…"); }
      return layer(4).state === "done" ? h("p", { class: "mono", text: "Nothing to rank." }) : null;
    }
    var serious = list.filter(function (f) { return f.severity === "critical" || f.severity === "high"; }).length;
    var review = list.filter(function (f) { return f.needs_review; }).length;
    return h("div", { class: "stats" },
      stat(fmt(list.length), plural(list.length, "target") + " ranked"),
      stat(fmt(serious), "critical or high"),
      stat(fmt(list.filter(raisedByRule).length), "raised by code rules"),
      stat(fmt(review), "failed the evidence check"));
  }

  function renderReason() {
    var list = findingsSorted();
    if (!list.length) { return null; }
    return list.map(function (f) {
      var raised = raisedByRule(f);
      var blast = "";
      if (typeof f.blast_radius === "number" && typeof f.classified_blast_radius === "number" && f.classified_blast_radius !== f.blast_radius) {
        var why = /versus classify/.test(f.blast_override_reason || "") ? "" : f.blast_override_reason;
        blast = "Blast radius changed from " + f.classified_blast_radius + " to " + f.blast_radius + (why ? ": " + why : "") + ".";
      }
      return h("article", { class: "judg" },
        h("div", null, sev(f.severity)),
        tname(f.target, kindLabel(f.target, f.kind, f.evidence)),
        h("div", null,
          h("h3", { text: f.risk || "No explanation." }),
          raised ? h("p", { class: "rule" }, h("b", { text: "Rule" }),
            "Model said " + f.model_severity + ", raised to " + f.severity + (f.floor_reason ? ": " + f.floor_reason : ".")) : null,
          !raised && f.floor_reason ? h("p", { class: "rule" }, h("b", { text: "Rule" }), f.floor_reason + ".") : null,
          f.ceiling_note ? h("p", { class: "rule" }, h("b", { text: "Rule" }), f.ceiling_note) : null,
          f.uncertain_about ? h("p", { class: "unsure", text: "Unsure: " + f.uncertain_about }) : null,
          f.needs_review ? h("p", { class: "unsure", text: "Needs review: the model’s explanation failed the evidence check, so code rules set the severity." }) : null,
          blast ? h("p", { class: "unsure", text: blast }) : null,
          evidenceKeys(f)));
    });
  }

  /* ---------- layer 05: report ---------- */

  function groupsOf(list) {
    return {
      today: list.filter(function (f) { return f.severity === "critical" || f.severity === "high"; }),
      review: list.filter(function (f) { return f.severity === "medium" || f.severity === "low"; }),
      safe: list.filter(function (f) { return f.severity === "info"; })
    };
  }

  function verdict(groups) {
    var today = groups.today;
    if (today.length) {
      var crit = today.filter(function (f) { return f.severity === "critical"; }).length;
      var high = today.length - crit;
      var split = [crit ? crit + " critical" : "", high ? high + " high" : ""].filter(Boolean).join(", ");
      return "Fix " + today.length + " " + plural(today.length, "thing") + " today: " + split + ".";
    }
    if (groups.review.length) { return "Nothing to fix today. " + groups.review.length + " " + plural(groups.review.length, "thing") + " to review."; }
    return "Nothing to fix today. Every outside target checked out.";
  }

  // Fix today comes from a code rule; say which, so the model is never the only reason.
  function whyLine(f) {
    var text = f.floor_reason ? f.floor_reason + "." : f.ceiling_note || "";
    if (!text) { return null; }
    return h("p", { class: "fixline why" }, h("span", { class: "fixtype", text: "Why" }), text);
  }

  function modelHigh(f) { return f.model_severity === "critical" || f.model_severity === "high" ? 1 : 0; }

  function findingNode(f, rank) {
    return h("article", { class: "finding" },
      h("div", { class: "rank", text: pad(rank) }),
      h("div", { class: "body" },
        h("h4", { text: f.target }),
        h("p", { class: "head", text: f.risk }),
        whyLine(f),
        h("p", { class: "fixline" }, h("span", { class: "fixtype", text: "Fix" }), f.fix),
        h("div", { class: "where", text: whereText(f) })),
      h("div", { class: "sevcol" }, sev(f.severity)));
  }

  function summaryReport() {
    if (layer(5).state !== "done") { return null; }
    var list = findingsSorted();
    var groups = groupsOf(list);
    var budget = (S.done && S.done.budget_targets) || [];
    var note = budget.length ? budget.length + " lower-priority " + plural(budget.length, "target was", "targets were") + " not sent to the agent; code checks still ran." : "";
    if (!list.length && S.gather && !S.gather.actionable) { note = "Nothing in this target could change hands."; }
    return [
      note ? h("p", { class: "verdict-src mono", text: note }) : null,
      h("div", { class: "tally" },
        h("div", { class: "today" }, h("b", { text: String(groups.today.length) }), h("span", { text: "Fix today" })),
        h("div", null, h("b", { text: String(groups.review.length) }), h("span", { text: "Review" })),
        h("div", null, h("b", { text: String(groups.safe.length) }), h("span", { text: "Checked and safe" })))
    ];
  }

  function renderReport() {
    if (layer(5).state !== "done") { return null; }
    var list = findingsSorted();
    var groups = groupsOf(list);
    var rank = 0;
    function section(key, title, items, open) {
      if (!items.length) { return h("div", { class: "group" }, h("h3", null, title, h("span", { text: "0" })), h("p", { class: "empty mono", text: "Nothing here." })); }
      var body = items.map(function (f) { rank += 1; return findingNode(f, rank); });
      return open
        ? h("div", { class: "group" }, h("h3", null, title, h("span", { text: String(items.length) })), body)
        : h("div", { class: "group" }, more("r-" + key, title + " · " + items.length, body));
    }
    // Muse Spark's own high calls lead Review, so a call without a rule behind it stays in sight
    groups.review.sort(function (a, b) { return modelHigh(b) - modelHigh(a); });
    var actions = [
      S.scanId && S.mode !== "demo" && S.shareable ? h("button", { class: "btn", type: "button", onclick: copyShare, text: "Copy share link" }) : null,
      h("button", { class: "btn", type: "button", onclick: copyMarkdown, text: "Copy as Markdown" }),
      h("button", { class: "btn", type: "button", onclick: downloadJson, text: "Download JSON" })
    ];
    return [
      section("today", "Fix today", groups.today, true),
      section("review", "Review", groups.review, true),
      section("safe", "Checked and safe", groups.safe, false),
      h("div", { class: "actions" }, actions)
    ];
  }

  /* ---------- rendering ---------- */

  var SUMMARY = [null, summaryGather, summaryClassify, summaryInvestigate, summaryReason, summaryReport];
  var RENDER = [null, renderGather, renderClassify, renderInvestigate, renderReason, renderReport];

  function renderLayer(n) {
    var result = $("#r" + n);
    var box = $("#c" + n);
    var open = $$("details[open]", box).map(function (d) { return d.getAttribute("data-key"); });
    var summary = SUMMARY[n]();
    var made = RENDER[n]();
    var details = made == null ? [] : [].concat(made).filter(function (node) { return node != null && node !== false; });
    result.replaceChildren();
    add(result, summary != null ? [].concat(summary) : details.length ? [] : [wait(S.failed ? "Not run." : WAITING[n])]);
    box.replaceChildren();
    add(box, details);
    $$("details", box).forEach(function (d) {
      if (open.indexOf(d.getAttribute("data-key")) !== -1) { d.open = true; }
    });
    showDetails(n);
  }

  function showDetails(n) {
    var box = $("#c" + n);
    var button = $('[data-toggle="' + n + '"]');
    var has = box.childNodes.length > 0;
    var open = has && OPEN[n];
    button.hidden = !has;
    box.hidden = !open;
    button.setAttribute("aria-expanded", open ? "true" : "false");
    button.textContent = open ? "Hide details" : "Show details";
    $("#layer-" + n).setAttribute("data-open", open ? "true" : "false");
  }

  function layerSummary(n) {
    if (n === 1) {
      if (!S.gather) { return S.fromReport ? "Not in saved report" : "Done"; }
      var t = S.gather.targets_total != null ? S.gather.targets_total : 0;
      return fmt(t) + " " + plural(t, "target");
    }
    if (n === 2) {
      if (!S.classified) { return S.fromReport ? "Not in saved report" : "Done"; }
      return fmt(S.classified.total) + " classified";
    }
    if (n === 3) {
      var checked = Object.keys(S.pre).length || Object.keys(S.ranked).length;
      return fmt(checked) + " checked" + (S.calls ? " · " + S.calls + " agent tool " + plural(S.calls, "call") : "");
    }
    if (n === 4) { return fmt(Object.keys(S.ranked).length) + " ranked"; }
    return groupsOf(findingsSorted()).today.length + " to fix today";
  }

  function layerStatus(n) {
    var l = layer(n);
    if (l.state === "error") { return "Stopped"; }
    if (l.state === "pending") { return S.failed ? "Not run" : "Waiting"; }
    if (l.state === "running") {
      if (n === 3) {
        var total = S.gather && S.gather.targets_total != null ? S.gather.targets_total : 0;
        var seen = Object.keys(S.pre).length;
        return total ? "Running · " + Math.min(seen, total) + "/" + total : "Running…";
      }
      if (n === 4) {
        // targets with low exposure and no hard signal are never ranked
        var ranked = Object.keys(S.ranked).length;
        var of = Object.keys(S.pre).filter(function (key) { return S.pre[key].next !== "low_exposure"; }).length;
        return of ? "Running · " + Math.min(ranked, of) + "/" + of : "Running…";
      }
      return "Running…";
    }
    var took = l.t0 != null && l.t1 != null && !S.fromReport && S.mode !== "demo" ? l.t1 - l.t0 : 0;
    return layerSummary(n) + (took >= 0.05 ? " · " + secs(took) : "");
  }

  function renderChrome() {
    for (var n = 1; n <= 5; n += 1) {
      var state = layer(n).state;
      var status = layerStatus(n);
      $('.slab[data-layer="' + n + '"]').setAttribute("data-state", state);
      var li = $('#stack-list li[data-layer="' + n + '"]');
      li.setAttribute("data-state", state);
      $(".sl-st", li).textContent = status;
      var section = $("#layer-" + n);
      section.setAttribute("data-state", state);
      $(".lstatus", section).textContent = status;
      var engine = n === 1 && S.kind === "website" ? "code · page fetch + parse" : scripted() && DEMO_ENGINE[n] ? DEMO_ENGINE[n] : ENGINE[n];
      $(".lengine", section).textContent = engine;
    }
    var art = $(".stack-cell");
    art.setAttribute("data-scan", S.mode === "idle" ? "idle" : S.failed ? "failed" : S.finished ? "done" : "running");
    renderRun();
    renderNotices();
  }

  function renderRun() {
    var run = $("#run");
    if (S.mode === "idle") { run.hidden = true; return; }
    run.hidden = false;
    var parts = [S.target || "…"];
    if (S.mode === "demo") { parts.push("demo replay"); }
    else if (S.kind) { parts.push(KIND_LABEL[S.kind] || S.kind); }
    if (S.mode === "shared") { parts.push("shared scan"); }
    if (!S.finished && !S.failed) {
      parts.push("scanning " + clock(Date.now() - S.clientStart));
    } else if (S.mode !== "demo") {
      if (S.startedTs != null && S.doneTs != null) { parts.push(secs(S.doneTs - S.startedTs)); }
      if (S.calls) { parts.push(S.calls + " agent tool " + plural(S.calls, "call")); }
      var cost = S.done && typeof S.done.cost_usd === "number" ? S.done.cost_usd : null;
      if (cost != null) { parts.push(money(cost) + " model cost"); }
    }
    if (S.failed) { parts.push("stopped"); }
    $("#run-text").textContent = parts.join(" · ");
  }

  function renderNotices() {
    var list = S.notices.slice();
    if (S.mode === "demo") {
      list.unshift(scripted()
        ? "Demo replay: a recorded scan of the fixture repo that ships with Trustline, made offline with stubbed lookups and a scripted stand-in for Muse Spark. Paste a repository for a live scan."
        : "Demo replay: a recorded live scan of the fixture repo that ships with Trustline, with Muse Spark and real lookups. Paste a repository to scan your own.");
    }
    var budget = (S.done && S.done.budget_targets) || [];
    if (budget.length) { list.push("The scan hit its model budget, so " + budget.length + " lower-priority " + plural(budget.length, "target was", "targets were") + " not investigated."); }
    var box = $("#notices");
    box.hidden = !list.length;
    box.replaceChildren();
    list.forEach(function (text) { box.appendChild(h("p", null, h("b", { text: "Note: " }), text)); });
  }

  /* ---------- error dialog ---------- */

  var lastFocus = null;
  var dialogAction = null;

  function showDialog(message, detail, action) {
    lastFocus = document.activeElement;
    $("#win-msg").textContent = message;
    $("#win-detail").textContent = detail || "";
    var act = $("#win-act");
    dialogAction = action || null;
    act.hidden = !action;
    act.textContent = action ? action.label : "";
    $("#win").hidden = false;
    (action ? act : $("#win-ok")).focus();
  }

  function hideDialog() {
    $("#win").hidden = true;
    var target = lastFocus && lastFocus.focus && document.body.contains(lastFocus) ? lastFocus : $("#target");
    target.focus();
  }

  $("#win-ok").addEventListener("click", hideDialog);
  $("#win-act").addEventListener("click", function () {
    var action = dialogAction;
    hideDialog();
    if (action) { action.run(); }
  });
  $("#win").addEventListener("keydown", function (event) {
    if (event.key === "Escape") { event.preventDefault(); hideDialog(); return; }
    if (event.key !== "Tab") { return; }
    var buttons = $$(".win-ok", $("#win")).filter(function (b) { return !b.hidden; });
    var index = buttons.indexOf(document.activeElement);
    event.preventDefault();
    buttons[(index + (event.shiftKey ? -1 : 1) + buttons.length) % buttons.length].focus();
  });

  var DEMO_ACTION = { label: "Watch demo", run: function () { startDemo(); } };

  /* ---------- about, and the file tray's cards ---------- */

  var aboutFocus = null;

  function showAbout() {
    aboutFocus = document.activeElement;
    $("#about").hidden = false;
    $("#about-ok").focus();
  }

  function hideAbout() {
    $("#about").hidden = true;
    var target = aboutFocus && aboutFocus.focus && document.body.contains(aboutFocus) ? aboutFocus : $("#target");
    target.focus();
  }

  $("#about-ok").addEventListener("click", hideAbout);
  $("#about").addEventListener("keydown", function (event) {
    if (event.key === "Escape") { event.preventDefault(); hideAbout(); return; }
    if (event.key === "Tab") { event.preventDefault(); $("#about-ok").focus(); }
  });

  function highlight(el) {
    el.classList.remove("flash");
    void el.offsetWidth;  // restart the animation on a second click
    el.classList.add("flash");
    window.setTimeout(function () { el.classList.remove("flash"); }, 1500);
  }

  function smooth() { return window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth"; }

  function goToLayer(n) {
    var section = $("#layer-" + n);
    section.scrollIntoView({ behavior: smooth(), block: "start" });
    var heading = $("#l" + n);
    heading.setAttribute("tabindex", "-1");
    heading.focus({ preventScroll: true });
    highlight(section);
  }

  function goToRun() {
    var run = $("#run");
    if (run.hidden) {
      // no scan yet, so no run details: the box to start one
      $("#target").focus();
      highlight($(".input-cell"));
      return;
    }
    run.open = true;
    run.scrollIntoView({ behavior: smooth(), block: "nearest" });
    $("summary", run).focus();
  }

  // cards back to front: layers 01 to 05, Run details, Repos to try, About
  document.addEventListener("trustline:card", function (event) {
    var index = Number(event.detail);
    if (index >= 0 && index <= 4) { goToLayer(index + 1); }
    else if (index === 5) { goToRun(); }
    else if (index === 6) { openDrawer(); }
    else if (index === 7) { showAbout(); }
  });

  /* ---------- starting and following scans ---------- */

  function setBusy(on) {
    $("#scan-btn").disabled = on;
    $("#scan-label").textContent = on ? "Scanning…" : "Scan";
    $("#target").readOnly = on;
    $$(".dr-scan").forEach(function (btn) { btn.disabled = on; });
    if (timer) { clearInterval(timer); timer = null; }
    if (on) { timer = setInterval(function () { renderRun(); }, 1000); }
  }

  function closeSource() {
    if (S.source) { S.source.close(); S.source = null; }
    if (S.abort) { S.abort.abort(); S.abort = null; }
    if (S.pollTimer) { clearTimeout(S.pollTimer); S.pollTimer = null; }
  }

  function reset(meta) {
    closeSource();
    S = fresh();
    Object.keys(meta || {}).forEach(function (key) { S[key] = meta[key]; });
    mark();
  }

  function normalize(raw) {
    var value = (raw || "").trim();
    if (!value) { return ""; }
    if (/^[A-Za-z0-9-]+\/[\w.-]+$/.test(value)) { return "https://github.com/" + value.replace(/\.git$/, ""); }
    if (!/^https?:\/\//i.test(value) && /^[\w-]+(\.[\w-]+)+(\/|$)/.test(value)) { return "https://" + value; }
    return value;
  }

  function detectKind(value) {
    if (/^https?:\/\/(www\.)?github\.com\/[^/]+\/[^/#?]+/i.test(value)) { return "repo"; }
    if (/^https?:\/\/[\w-]+(\.[\w-]+)+(:\d+)?(\/|$|\?|#)/i.test(value)) { return "website"; }
    return "";
  }

  function startScan(raw) {
    var target = normalize(raw);
    var kind = detectKind(target);
    if (!kind) {
      showDialog("This is not a GitHub repository or website.", "Paste github.com/owner/repo, or a full address like https://example.com.");
      return;
    }
    reset({ mode: "live", kind: kind, target: target });
    setBusy(true);
    if (canStream()) { streamScan(target, raw); return; }
    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: target })
    })
      .then(function (res) {
        return res.json().catch(function () { return {}; }).then(function (body) {
          return { status: res.status, ok: res.ok, body: body };
        });
      })
      .then(function (out) {
        if (!out.ok) { refused(out.status, out.body, raw); return; }
        var id = String(out.body.scan_id);
        S.scanId = id;
        S.kind = out.body.kind || S.kind;
        S.target = out.body.target || S.target;
        history.replaceState(null, "", scanQuery(id));
        openStream("/api/scan/" + encodeURIComponent(id) + "/events");
      })
      .catch(function () { refused(0, {}, raw); });
  }

  function canStream() {
    return typeof window.ReadableStream === "function" && typeof window.TextDecoder === "function" &&
      typeof window.AbortController === "function" && typeof Response !== "undefined" && "body" in Response.prototype;
  }

  // Start and follow the scan in one request. That is all a serverless host
  // (Vercel) guarantees; elsewhere the job is also kept for share links.
  function streamScan(target, raw) {
    var mine = S;
    S.abort = new AbortController();
    fetch("/api/scan/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
      body: JSON.stringify({ target: target }),
      signal: S.abort.signal
    })
      .then(function (res) {
        if (mine !== S) { return null; }
        var type = res.headers.get("content-type") || "";
        if (!res.ok || type.indexOf("text/event-stream") === -1) {
          return res.json().catch(function () { return {}; }).then(function (body) {
            if (mine === S) { refused(res.status, body, raw); }
          });
        }
        return readStream(res.body.getReader(), mine);
      })
      .catch(function () {
        if (mine !== S) { return; }
        if (S.streamed) { streamEnded(); } else { refused(0, {}, raw); }
      });
  }

  function readStream(reader, mine) {
    var decoder = new TextDecoder();
    var buffer = "";
    function frame(chunk) {
      var data = chunk.split("\n").filter(function (line) { return line.indexOf("data:") === 0; })
        .map(function (line) { return line.slice(5).replace(/^ /, ""); }).join("\n");
      if (!data) { return; } // a keep-alive comment
      var ev;
      try { ev = JSON.parse(data); } catch (err) { return; }
      S.streamed = true;
      if (ev.type === "started" && ev.scan_id) {
        S.scanId = String(ev.scan_id);
        S.shareable = ev.shareable !== false;
        if (S.shareable) { history.replaceState(null, "", scanQuery(S.scanId)); }
      }
      consume(ev);
      if (ev.type === "done" || ev.type === "error") { ended(ev); }
    }
    function pump() {
      return reader.read().then(function (step) {
        if (mine !== S) { reader.cancel(); return; }
        if (step.done) { streamEnded(); return; }
        buffer += decoder.decode(step.value, { stream: true }).replace(/\r\n/g, "\n");
        var cut = buffer.indexOf("\n\n");
        while (cut !== -1) {
          frame(buffer.slice(0, cut));
          buffer = buffer.slice(cut + 2);
          cut = buffer.indexOf("\n\n");
        }
        return pump();
      });
    }
    return pump();
  }

  function streamEnded() {
    S.abort = null;
    if (S.finished || S.failed) { return; }
    setBusy(false);
    if (S.shareable && S.scanId) {
      showDialog("The live scan connection dropped.", "The scan may still be running on the server.", { label: "Reconnect", run: reattach });
      return;
    }
    showDialog("The live scan connection dropped.", "The host ended the request before the scan finished. Hosts like Vercel stop a request after five minutes on the free plan.",
      { label: "Retry", run: function () { startScan(S.target); } });
  }

  function refused(status, body, raw) {
    var detail = String((body && (body.error || body.detail)) || "");
    reset({});
    setBusy(false);
    history.replaceState(null, "", window.location.pathname);
    var retry = { label: "Retry", run: function () { startScan(raw); } };
    if (status === 503) { showDialog("Model scans aren’t configured on this server.", "Repository scans can run in free code-only mode. Model analysis requires MODEL_API_KEY and TRUSTMAP_ENABLE_MODEL_SCANS=1.", DEMO_ACTION); }
    else if (status === 429) { showDialog("Trustline is busy.", detail || "Too many scans right now.", DEMO_ACTION); }
    else if (status === 400) { showDialog("This target can’t be scanned.", detail); }
    else if (status === 0) { showDialog("Could not reach the Trustline server.", "Check that it is running, then try again.", retry); }
    else { showDialog("The scan could not be started.", detail || "The server answered HTTP " + status + ".", retry); }
  }

  function startDemo() {
    $("#win").hidden = true;
    reset({ mode: "demo", kind: "path", target: "demo repo" });
    setBusy(true);
    history.replaceState(null, "", "?demo=1");
    openStream("/api/scan/demo/events");
  }

  function openShared(id) {
    reset({ mode: "shared", scanId: id });
    setBusy(true);
    fetch("/api/scan/" + encodeURIComponent(id))
      .then(function (res) {
        return res.json().catch(function () { return {}; }).then(function (body) { return { status: res.status, body: body }; });
      })
      .then(function (out) {
        if (out.status === 200 || out.status === 409) {
          S.target = out.body.target || S.target;
          S.kind = out.body.kind || S.kind;
          openStream("/api/scan/" + encodeURIComponent(id) + "/events");
          return;
        }
        if (out.status === 500) {
          S.target = out.body.target || S.target;
          consume({ type: "error", message: out.body.error });
          setBusy(false);
          showDialog("That scan stopped with an error.", String(out.body.error || ""));
          return;
        }
        gone();
      })
      .catch(gone);
  }

  function gone() {
    reset({});
    setBusy(false);
    history.replaceState(null, "", window.location.pathname);
    showDialog("That scan is no longer available.", "Shared links last until the server restarts. Run the scan again.");
  }

  // Following a scan again replays it from the first event.
  function reattach() {
    var keep = { mode: S.mode, scanId: S.scanId, kind: S.kind, target: S.target };
    reset(keep);
    setBusy(true);
    openStream(S.mode === "demo" ? "/api/scan/demo/events" : "/api/scan/" + encodeURIComponent(S.scanId) + "/events");
  }

  function openStream(url) {
    closeSource();
    var source;
    try {
      source = new EventSource(url);
    } catch (err) {
      // No EventSource here (an old webview, an extension). The scan is
      // already running on the server, so wait it out instead of losing it.
      waitWithoutStream();
      return;
    }
    S.source = source;
    source.onmessage = function (message) {
      var ev;
      try { ev = JSON.parse(message.data); } catch (err) { return; }
      S.streamed = true;
      consume(ev);
      if (ev.type === "done" || ev.type === "error") {
        closeSource();
        ended(ev);
      }
    };
    source.onerror = function () {
      closeSource();
      if (S.finished || S.failed) { return; }
      if (!S.streamed) {
        // Not one frame arrived: the stream is the problem, not the scan.
        // A proxy that buffers the response looks exactly like this.
        waitWithoutStream();
        return;
      }
      setBusy(false);
      showDialog("The live scan connection dropped.", "The scan may still be running on the server.", { label: "Reconnect", run: reattach });
    };
  }

  function ended(ev) {
    setBusy(false);
    if (ev.type === "error") {
      var again = S.mode === "demo" ? DEMO_ACTION : S.target && S.mode === "live"
        ? { label: "Retry", run: function () { startScan(S.target); } } : null;
      showDialog("The scan stopped.", S.failed, again);
      return;
    }
    // on a serverless host that request would reach an instance without the job;
    // the streamed events already hold the whole report
    if (S.shareable) { loadReport(); }
  }

  // The finished report has the server's own ordering and totals for export.
  function loadReport() {
    var url = S.mode === "demo" ? "/api/scan/demo" : "/api/scan/" + encodeURIComponent(S.scanId);
    fetch(url)
      .then(function (res) {
        if (!res.ok) { throw new Error("report " + res.status); }
        return res.json();
      })
      .then(function (report) {
        S.report = report;
        mark(4, 5);
      })
      .catch(function () {});
  }

  // Fallback when live events can't reach this page: poll for the finished report.
  function waitWithoutStream() {
    if (S.mode === "demo") {
      S.notices.push("Live updates aren't available in this browser, so the demo can't play. Showing its finished report instead.");
      fetch("/api/scan/demo")
        .then(function (res) { return res.json(); })
        .then(fromReport)
        .catch(function () { setBusy(false); showDialog("The demo could not be loaded.", ""); });
      return;
    }
    S.notices.push("Live updates aren't available in this browser. Waiting for the report…");
    mark();
    var attempts = 0;
    function poll() {
      if (S.finished) { return; }
      attempts += 1;
      if (attempts > POLL_LIMIT) {
        showDialog("The scan is taking longer than expected.", "", { label: "Keep waiting", run: function () { attempts = 0; poll(); } });
        return;
      }
      fetch("/api/scan/" + encodeURIComponent(S.scanId))
        .then(function (res) {
          if (res.status === 409) { return null; }
          return res.json().catch(function () { return {}; }).then(function (body) { return { status: res.status, body: body }; });
        })
        .then(function (out) {
          if (!out) { S.pollTimer = setTimeout(poll, POLL_EVERY_MS); return; }
          if (out.status === 200) { fromReport(out.body); return; }
          if (out.status === 404) { gone(); return; }
          consume({ type: "error", message: out.body.error || "The scan failed." });
          setBusy(false);
          showDialog("The scan stopped.", S.failed, { label: "Retry", run: function () { startScan(S.target); } });
        })
        .catch(function () {
          setBusy(false);
          showDialog("Lost contact with the Trustline server.", "", { label: "Keep waiting", run: function () { setBusy(true); attempts = 0; poll(); } });
        });
    }
    S.pollTimer = setTimeout(poll, POLL_EVERY_MS);
  }

  // Draw the layers a finished report can fill without its event stream.
  function fromReport(report) {
    S.notices = S.notices.map(function (text) {
      return text.indexOf("Waiting for the report") === -1 ? text
        : "Live updates aren't available in this browser, so the layers below come from the finished report.";
    });
    S.fromReport = true;
    S.report = report;
    S.target = report.target || S.target;
    S.kind = report.kind || S.kind;
    (report.findings || []).forEach(function (f) { S.ranked[noteTarget(f.target)] = f; });
    S.done = { cost_usd: report.cost_usd, budget_targets: report.budget_targets || [] };
    [1, 2, 3, 4, 5].forEach(function (n) { layer(n).state = "done"; });
    S.finished = true;
    setBusy(false);
    mark();
  }

  /* ---------- exports ---------- */

  function flash(button, text) {
    var before = button.textContent;
    button.textContent = text;
    setTimeout(function () { button.textContent = before; }, 1600);
  }

  function copy(text, button) {
    if (!navigator.clipboard || !navigator.clipboard.writeText) { flash(button, "Copy not available"); return; }
    navigator.clipboard.writeText(text)
      .then(function () { flash(button, "Copied"); })
      .catch(function () { flash(button, "Copy failed"); });
  }

  function copyShare(event) {
    copy(window.location.origin + window.location.pathname + scanQuery(S.scanId), event.currentTarget);
  }

  function markdown() {
    var list = findingsSorted();
    var groups = groupsOf(list);
    var lines = ["# Trustline report: " + S.target, "", verdict(groups), ""];
    [["today", "Fix today"], ["review", "Review"], ["safe", "Checked and safe"]].forEach(function (pair) {
      var items = groups[pair[0]];
      if (!items.length) { return; }
      lines.push("## " + pair[1], "");
      items.forEach(function (f) {
        lines.push("- **" + String(SEV_LABEL[f.severity] || f.severity).toUpperCase() + "** `" + f.target + "`: " + f.risk);
        var why = f.floor_reason ? f.floor_reason + "." : f.ceiling_note || "";
        if (why) { lines.push("  - Why: " + why); }
        lines.push("  - Fix: " + f.fix);
        var where = whereList(f);
        if (where.length) { lines.push("  - Where: " + where.join(", ")); }
      });
      lines.push("");
    });
    return lines.join("\n");
  }

  function copyMarkdown(event) { copy(markdown(), event.currentTarget); }

  function downloadJson() {
    var data = {
      tool: "Trustline",
      generated_at: new Date().toISOString(),
      report: S.report || { target: S.target, kind: S.kind, findings: findingsSorted() },
      gather: S.gather,
      classified: S.classified
    };
    var url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
    var link = $("#download");
    link.href = url;
    link.download = "trustline-" + String(S.target || "scan").replace(/^https?:\/\//, "").replace(/[^\w.-]+/g, "-").slice(0, 60) + ".json";
    link.click();
    setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
  }

  /* ---------- repos to try: a side panel, filled from /static/targets.json ---------- */

  var EXPECT_CLASS = { critical: "critical", high: "high", flagged: "medium", "mostly safe": "info" };
  var drawer = $("#targets");
  var drawerTab = $("#targets-tab");
  var drawerList = $("#targets-list");
  var targetsLoaded = false;

  function openDrawer() {
    drawer.hidden = false;
    drawerTab.setAttribute("aria-expanded", "true");
    if (!targetsLoaded) { loadTargets(); }
    $("#targets-close").focus();
  }

  function closeDrawer() {
    if (drawer.hidden) { return; }
    drawer.hidden = true;
    drawerTab.setAttribute("aria-expanded", "false");
    drawerTab.focus();
  }

  function loadTargets() {
    targetsLoaded = true;
    drawerList.replaceChildren(pending("Loading…"));
    fetch("/static/targets.json")
      .then(function (res) {
        if (!res.ok) { throw new Error("targets " + res.status); }
        return res.json();
      })
      .then(renderTargets)
      .catch(function () {
        targetsLoaded = false;
        drawerList.replaceChildren(pending("The list didn’t load. Close this panel and open it again."));
      });
  }

  function renderTargets(data) {
    drawerList.replaceChildren();
    add(drawerList, [
      data.note ? h("p", { class: "dr-note mono", text: data.note }) : null,
      (data.groups || []).map(function (group) {
        return h("section", { class: "dr-group" },
          h("h3", { text: group.title }),
          group.blurb ? h("p", { class: "dr-blurb", text: group.blurb }) : null,
          (group.repos || []).map(repoCard));
      })
    ]);
    $$(".dr-scan", drawerList).forEach(function (btn) { btn.disabled = $("#scan-btn").disabled; });
  }

  function repoCard(item) {
    var expect = String(item.expect || "");
    return h("article", { class: "dr-item" },
      h("div", { class: "dr-top" },
        h("span", { class: "dr-repo", text: item.repo }),
        expect ? h("span", { class: "sev sev-" + (EXPECT_CLASS[expect] || "low"), text: expect }) : null),
      item.about ? h("p", { class: "dr-about", text: item.about }) : null,
      h("p", { class: "dr-finding", text: item.finding }),
      item.where ? h("p", { class: "dr-meta", text: "Where: " + item.where }) : null,
      item.checked ? h("p", { class: "dr-meta", text: "Checked: " + item.checked }) : null,
      h("div", { class: "dr-foot" },
        h("span", { class: "dr-meta", text: fmt(item.targets) + " targets · " + (item.run || "") }),
        h("button", {
          class: "dr-scan",
          type: "button",
          "aria-label": "Scan " + item.repo,
          onclick: function () { scanFromList(item.repo); },
          text: "Scan"
        })));
  }

  function scanFromList(repo) {
    $("#target").value = "github.com/" + repo;
    closeDrawer();
    startScan($("#target").value);
  }

  drawerTab.addEventListener("click", openDrawer);
  $("#targets-close").addEventListener("click", closeDrawer);
  drawer.addEventListener("keydown", function (event) {
    if (event.key === "Escape") { event.preventDefault(); closeDrawer(); }
  });

  /* ---------- wiring ---------- */

  $("#scan-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var value = $("#target").value.trim();
    if (!value) { $("#target").focus(); return; }
    startScan(value);
  });
  $$("[data-toggle]").forEach(function (button) {
    button.addEventListener("click", function () {
      var n = Number(button.getAttribute("data-toggle"));
      OPEN[n] = !OPEN[n];
      showDetails(n);
    });
  });

  mark();

  var params = new URLSearchParams(window.location.search);
  var scanParam = params.get("scan");
  if (params.get("demo") === "1") {
    startDemo();
  } else if (scanParam && /^[A-Za-z0-9_-]+$/.test(scanParam)) {
    openShared(scanParam);
  }
})();
