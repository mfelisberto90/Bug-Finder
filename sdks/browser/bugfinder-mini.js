(function (root) {
  "use strict";

  var cfg = {
    endpoint: "",
    dsnKey: "",
    release: "",
    environment: "production",
    maxBreadcrumbs: 50,
    user: null,
    tags: {},
    breadcrumbs: [],
    logBuffer: [],
    flushTimer: null
  };

  function parseDsn(dsn) {
    try {
      var u = new URL(dsn);
      var key = u.username;
      var pid = u.pathname.replace(/^\/+|\/+$/g, "").split("/").pop();
      if (!key || !pid) return null;
      return {
        endpoint: u.protocol + "//" + u.host + "/api/" + encodeURIComponent(pid) + "/envelope/",
        dsnKey: key
      };
    } catch (_) {
      return null;
    }
  }

  function addBreadcrumb(crumb) {
    cfg.breadcrumbs.push({
      timestamp: Date.now() / 1000,
      type: crumb.type || "default",
      category: crumb.category || "custom",
      level: crumb.level || "info",
      message: String(crumb.message || "").slice(0, 500),
      data: crumb.data || undefined
    });
    if (cfg.breadcrumbs.length > cfg.maxBreadcrumbs) {
      cfg.breadcrumbs.shift();
    }
  }

  function parseStack(stackStr) {
    if (!stackStr) return [];
    return String(stackStr)
      .split("\n")
      .slice(1, 30)
      .map(function (line) {
        var m = line.match(/^\s*at\s+(?:(.+?)\s+\()?(.+?):(\d+):(\d+)\)?/) ||
                line.match(/^\s*(.*?)@(.+?):(\d+):(\d+)/);
        if (!m) return { filename: line.trim().slice(0, 200), in_app: true };
        return {
          function: (m[1] || "<anonymous>").trim(),
          filename: m[2],
          lineno: Number(m[3]),
          colno: Number(m[4]),
          in_app: !m[2].includes("node_modules")
        };
      })
      .reverse();
  }

  function sendEnvelope(header, items) {
    if (!cfg.endpoint) return;
    var lines = [JSON.stringify(header)];
    for (var i = 0; i < items.length; i++) {
      lines.push(JSON.stringify(items[i][0]));
      lines.push(JSON.stringify(items[i][1]));
    }
    var body = lines.join("\n") + "\n";
    var url = cfg.endpoint + (cfg.dsnKey ? "?sentry_key=" + encodeURIComponent(cfg.dsnKey) : "");
    try {
      if (typeof fetch === "function") {
        fetch(url, {
          method: "POST",
          body: body,
          keepalive: true,
          headers: { "Content-Type": "text/plain;charset=UTF-8" }
        }).catch(function () {});
      }
    } catch (_) {}
  }

  function uuidHex() {
    var s = "";
    for (var i = 0; i < 32; i++) s += Math.floor(Math.random() * 16).toString(16);
    return s;
  }

  function captureException(err, extra) {
    var name = (err && err.name) || "Error";
    var message = (err && err.message) || String(err || "Unknown error");
    var frames = parseStack(err && err.stack);
    var eid = uuidHex();
    var payload = {
      event_id: eid,
      timestamp: Date.now() / 1000,
      platform: "javascript",
      level: "error",
      environment: cfg.environment,
      release: cfg.release || undefined,
      tags: cfg.tags,
      user: cfg.user || undefined,
      extra: extra || undefined,
      breadcrumbs: { values: cfg.breadcrumbs.slice() },
      request: { url: typeof location !== "undefined" ? location.href : "" },
      exception: {
        values: [{ type: name, value: message, stacktrace: { frames: frames } }]
      }
    };
    sendEnvelope(
      { event_id: eid, sent_at: new Date().toISOString(), dsn: cfg.rawDsn || undefined, sdk: { name: "bugfinder.mini", version: "1.0.0" } },
      [[{ type: "event" }, payload]]
    );
    return eid;
  }

  function captureMessage(msg, level) {
    var eid = uuidHex();
    sendEnvelope(
      { event_id: eid, sent_at: new Date().toISOString(), sdk: { name: "bugfinder.mini", version: "1.0.0" } },
      [[{ type: "event" }, {
        event_id: eid,
        timestamp: Date.now() / 1000,
        platform: "javascript",
        level: level || "info",
        environment: cfg.environment,
        release: cfg.release || undefined,
        message: String(msg),
        tags: cfg.tags,
        breadcrumbs: { values: cfg.breadcrumbs.slice() }
      }]]
    );
    return eid;
  }

  function flushLogs() {
    if (cfg.flushTimer) {
      clearTimeout(cfg.flushTimer);
      cfg.flushTimer = null;
    }
    if (!cfg.logBuffer.length) return;
    var batch = cfg.logBuffer.splice(0, 100);
    sendEnvelope(
      { sent_at: new Date().toISOString(), sdk: { name: "bugfinder.mini", version: "1.0.0" } },
      [[
        { type: "log", item_count: batch.length, content_type: "application/vnd.sentry.items.log+json" },
        { version: 2, items: batch }
      ]]
    );
  }

  function pushLog(level, body, attrs) {
    var wrapped = {};
    var src = attrs || {};
    if (cfg.environment) wrapped["sentry.environment"] = { value: cfg.environment, type: "string" };
    if (cfg.release) wrapped["sentry.release"] = { value: cfg.release, type: "string" };
    Object.keys(src).forEach(function (k) {
      var v = src[k];
      var t = typeof v === "number" ? (Number.isInteger(v) ? "integer" : "double") : typeof v === "boolean" ? "boolean" : "string";
      wrapped[k] = { value: t === "string" ? String(v) : v, type: t };
    });
    cfg.logBuffer.push({
      timestamp: Date.now() / 1000,
      level: level,
      body: String(body),
      attributes: wrapped
    });
    if (cfg.logBuffer.length >= 25) {
      flushLogs();
    } else if (!cfg.flushTimer) {
      cfg.flushTimer = setTimeout(flushLogs, 800);
    }
  }

  function init(options) {
    options = options || {};
    cfg.rawDsn = options.dsn || "";
    if (options.tunnel) {
      cfg.endpoint = options.tunnel;
      cfg.dsnKey = "";
    } else if (options.dsn) {
      var parsed = parseDsn(options.dsn);
      if (parsed) {
        cfg.endpoint = parsed.endpoint;
        cfg.dsnKey = parsed.dsnKey;
      }
    }
    cfg.release = options.release || "";
    cfg.environment = options.environment || "production";
    cfg.maxBreadcrumbs = options.maxBreadcrumbs || 50;

    if (typeof window !== "undefined") {
      window.addEventListener("error", function (ev) {
        if (ev && ev.error) captureException(ev.error);
        else if (ev && ev.message) captureMessage(ev.message, "error");
      });
      window.addEventListener("unhandledrejection", function (ev) {
        var reason = ev && ev.reason;
        captureException(reason instanceof Error ? reason : new Error(String(reason || "Unhandled rejection")));
      });
      window.addEventListener("click", function (ev) {
        var t = ev && ev.target;
        if (t && t.tagName) {
          addBreadcrumb({
            type: "ui",
            category: "ui.click",
            message: t.tagName.toLowerCase() + (t.id ? "#" + t.id : "")
          });
        }
      }, true);
      window.addEventListener("pagehide", flushLogs);
    }
  }

  root.BugFinder = {
    init: init,
    captureException: captureException,
    captureMessage: captureMessage,
    addBreadcrumb: addBreadcrumb,
    setUser: function (u) { cfg.user = u; },
    setTag: function (k, v) { cfg.tags[k] = v; },
    flushLogs: flushLogs,
    logger: {
      trace: function (m, a) { pushLog("trace", m, a); },
      debug: function (m, a) { pushLog("debug", m, a); },
      info: function (m, a) { pushLog("info", m, a); },
      warn: function (m, a) { pushLog("warn", m, a); },
      error: function (m, a) { pushLog("error", m, a); },
      fatal: function (m, a) { pushLog("fatal", m, a); }
    }
  };
})(typeof globalThis !== "undefined" ? globalThis : window);
