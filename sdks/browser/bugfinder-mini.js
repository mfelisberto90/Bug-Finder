(function (root) {
  "use strict";

  var origFetch = typeof root.fetch === "function" ? root.fetch : null;
  var curScript = typeof document !== "undefined" ? document.currentScript : null;

  var cfg = {
    endpoint: "",
    shieldEndpoint: "",
    dsnKey: "",
    rawDsn: "",
    release: "",
    environment: "production",
    maxBreadcrumbs: 50,
    user: null,
    tags: {},
    breadcrumbs: [],
    logBuffer: [],
    flushTimer: null,
    initialized: false,
    fetchWrapped: false,
    xhrWrapped: false,
    consoleWrapped: false,
    inConsole: false,
    slowMs: 5000,
    tracePropagation: false,
    traceId: "",
    sessionPinged: false,
    recentEvents: Object.create(null)
  };

  function sanitizeUrl(raw) {
    if (!raw) return "";
    var s = String(raw);
    var hashIdx = s.indexOf("#");
    if (hashIdx !== -1) s = s.slice(0, hashIdx);
    var qIdx = s.indexOf("?");
    if (qIdx === -1) return s;
    var base = s.slice(0, qIdx);
    var query = s.slice(qIdx + 1);
    var parts = query.split("&");
    var sensitive = /^(token|access_token|refresh_token|id_token|api_key|apikey|secret|password|passwd|pwd|code|session|sig|signature|jwt|auth|client_secret|sentry_key)$/i;
    for (var i = 0; i < parts.length; i++) {
      var eq = parts[i].indexOf("=");
      if (eq !== -1) {
        var k = parts[i].slice(0, eq);
        if (sensitive.test(k)) {
          parts[i] = k + "=[Filtered]";
        }
      }
    }
    return base + "?" + parts.join("&");
  }

  function nowMs() {
    try {
      if (typeof performance !== "undefined" && typeof performance.now === "function") {
        return performance.now();
      }
    } catch (_) {}
    return Date.now();
  }

  function isAppFrameUrl(raw) {
    if (!raw) return false;
    var low = String(raw).toLowerCase();
    return (
      low.indexOf("node_modules") === -1 &&
      low.indexOf("bugfinder-mini.js") === -1 &&
      low.indexOf("bugfinder-shield.js") === -1 &&
      low.indexOf("/_obs/m.js") === -1 &&
      low.indexOf("/_obs/s.js") === -1 &&
      low.indexOf("pptr:") !== 0 &&
      low.indexOf("puppeteer") === -1 &&
      low.indexOf("playwright") === -1 &&
      low.indexOf("chrome-extension://") !== 0 &&
      low.indexOf("moz-extension://") !== 0 &&
      low.indexOf("safari-extension://") !== 0 &&
      low.indexOf("safari-web-extension://") !== 0 &&
      low.indexOf("translate.googleapis.com") === -1 &&
      low.indexOf("translate-pa.googleapis.com") === -1 &&
      low.indexOf("googletagmanager.com") === -1 &&
      low.indexOf("google-analytics.com") === -1
    );
  }

  function isStreamingUrl(urlStr) {
    var low = String(urlStr || "").toLowerCase();
    return (
      low.indexOf("/stream") !== -1 ||
      low.indexOf("/tail") !== -1 ||
      low.indexOf("/events") !== -1
    );
  }

  function safeJsonStringify(obj) {
    try {
      var seen = typeof WeakSet === "function" ? new WeakSet() : [];
      return JSON.stringify(obj, function (_k, val) {
        if (typeof val === "bigint") return val.toString();
        if (val && typeof val === "object") {
          if (typeof WeakSet === "function") {
            if (seen.has(val)) return "[Circular]";
            seen.add(val);
          } else {
            if (seen.indexOf(val) !== -1) return "[Circular]";
            seen.push(val);
          }
        }
        return val;
      });
    } catch (_) {
      return "{}";
    }
  }

  function formatUnknown(val) {
    if (val instanceof Error) {
      return (val.name || "Error") + ": " + (val.message || "");
    }
    if (val === null) return "null";
    if (val === undefined) return "undefined";
    if (typeof Element !== "undefined" && val instanceof Element) {
      return "<" + val.tagName.toLowerCase() + (val.id ? "#" + val.id : "") + ">";
    }
    if (typeof val === "object") {
      if (typeof val.message === "string" && val.message) {
        return (typeof val.name === "string" && val.name ? val.name + ": " : "") + val.message;
      }
      var s = safeJsonStringify(val);
      if (s && s !== "{}") return s.slice(0, 500);
      return "[object]";
    }
    try {
      return String(val);
    } catch (_) {
      return "[unstringifiable]";
    }
  }

  function shouldDropDuplicate(fpKey) {
    var now = Date.now();
    var keys = Object.keys(cfg.recentEvents);
    if (keys.length > 100) {
      for (var i = 0; i < keys.length; i++) {
        if (now - cfg.recentEvents[keys[i]] >= 5000) {
          delete cfg.recentEvents[keys[i]];
        }
      }
      if (Object.keys(cfg.recentEvents).length > 100) {
        cfg.recentEvents = Object.create(null);
      }
    }
    var prev = cfg.recentEvents[fpKey];
    if (prev && now - prev < 5000) {
      return true;
    }
    cfg.recentEvents[fpKey] = now;
    return false;
  }

  function isOwnTelemetryUrl(rawUrl) {
    try {
      var s = String(rawUrl || "");
      if (!s) return false;
      if (cfg.endpoint && s.indexOf(cfg.endpoint) !== -1) return true;
      if (cfg.shieldEndpoint && s.indexOf(cfg.shieldEndpoint) !== -1) return true;
      return /\/api\/\d+\/(?:envelope|store|security|shield|otlp\/v1\/logs)\b/.test(s);
    } catch (_) {
      return false;
    }
  }

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
    var rawLines = String(stackStr).split("\n");
    if (
      rawLines.length > 0 &&
      !/^\s*at\s+/.test(rawLines[0]) &&
      !/^\s*[^@\s]*@(?:https?:|file:|blob:|webpack|eval|\/|\[native|.+:\d+:\d+)/.test(rawLines[0])
    ) {
      rawLines = rawLines.slice(1);
    }
    return rawLines
      .slice(0, 30)
      .filter(function (line) { return line && line.trim().length > 0; })
      .map(function (line) {
        var m = line.match(/^\s*at\s+(?:(.+?)\s+\()?(.+?):(\d+):(\d+)\)?/) ||
                line.match(/^\s*(.*?)@(.+?):(\d+):(\d+)/);
        if (!m) return { filename: line.trim().slice(0, 200), in_app: true };
        return {
          function: (m[1] || "<anonymous>").trim(),
          filename: m[2],
          lineno: Number(m[3]),
          colno: Number(m[4]),
          in_app: isAppFrameUrl(m[2])
        };
      })
      .reverse();
  }

  function sendEnvelope(header, items, preferBeacon) {
    if (!cfg.endpoint) return;
    var lines = [safeJsonStringify(header)];
    for (var i = 0; i < items.length; i++) {
      lines.push(safeJsonStringify(items[i][0]));
      lines.push(safeJsonStringify(items[i][1]));
    }
    var body = lines.join("\n") + "\n";
    var url = cfg.endpoint + (cfg.dsnKey ? "?sentry_key=" + encodeURIComponent(cfg.dsnKey) : "");
    try {
      if (
        preferBeacon &&
        typeof navigator !== "undefined" &&
        typeof navigator.sendBeacon === "function" &&
        body.length <= 60000
      ) {
        var blob = typeof Blob === "function"
          ? new Blob([body], { type: "text/plain;charset=UTF-8" })
          : body;
        if (navigator.sendBeacon(url, blob)) return;
      }
      if (origFetch) {
        origFetch.call(root, url, {
          method: "POST",
          body: body,
          keepalive: body.length <= 60000,
          headers: { "Content-Type": "text/plain;charset=UTF-8" }
        }).catch(function () {});
      }
    } catch (_) {}
  }

  function uuidHex() {
    var cryptoObj = root.crypto || root.msCrypto;
    if (cryptoObj && typeof cryptoObj.getRandomValues === "function") {
      var bytes = new Uint8Array(16);
      cryptoObj.getRandomValues(bytes);
      var out = "";
      for (var i = 0; i < bytes.length; i++) {
        out += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
      }
      return out;
    }
    var s = "";
    for (var j = 0; j < 32; j++) s += Math.floor(Math.random() * 16).toString(16);
    return s;
  }

  function captureException(err, extra) {
    var name = (err && typeof err.name === "string" && err.name) || "Error";
    var message = (err && typeof err.message === "string" && err.message)
      ? err.message
      : (err ? formatUnknown(err) : "Unknown error");
    var frames = parseStack(err && err.stack);
    var topFrame = frames.length ? frames[frames.length - 1].filename || "" : "";
    if (shouldDropDuplicate("ex:" + name + ":" + message.slice(0, 160) + ":" + topFrame)) {
      return null;
    }
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
      contexts: cfg.traceId ? { trace: { trace_id: cfg.traceId, span_id: uuidHex().slice(0, 16) } } : undefined,
      request: { url: typeof location !== "undefined" ? sanitizeUrl(location.href) : "" },
      exception: {
        values: [{ type: name, value: message, stacktrace: { frames: frames } }]
      }
    };
    sendEnvelope(
      { event_id: eid, sent_at: new Date().toISOString(), dsn: cfg.rawDsn || undefined, sdk: { name: "bugfinder.mini", version: "2.0.0" } },
      [[{ type: "event" }, payload]]
    );
    return eid;
  }

  function captureMessage(msg, level, extra) {
    var msgStr = formatUnknown(msg);
    var lvl = level || "info";
    if (shouldDropDuplicate("msg:" + lvl + ":" + msgStr.slice(0, 200))) {
      return null;
    }
    var eid = uuidHex();
    sendEnvelope(
      { event_id: eid, sent_at: new Date().toISOString(), dsn: cfg.rawDsn || undefined, sdk: { name: "bugfinder.mini", version: "2.0.0" } },
      [[{ type: "event" }, {
        event_id: eid,
        timestamp: Date.now() / 1000,
        platform: "javascript",
        level: lvl,
        environment: cfg.environment,
        release: cfg.release || undefined,
        message: msgStr,
        tags: cfg.tags,
        user: cfg.user || undefined,
        extra: extra || undefined,
        contexts: cfg.traceId ? { trace: { trace_id: cfg.traceId, span_id: uuidHex().slice(0, 16) } } : undefined,
        request: { url: typeof location !== "undefined" ? sanitizeUrl(location.href) : "" },
        breadcrumbs: { values: cfg.breadcrumbs.slice() }
      }]]
    );
    return eid;
  }

  function flushLogs(preferBeacon) {
    if (cfg.flushTimer) {
      clearTimeout(cfg.flushTimer);
      cfg.flushTimer = null;
    }
    if (!cfg.logBuffer.length) return;
    var batch = cfg.logBuffer.splice(0, 100);
    sendEnvelope(
      { sent_at: new Date().toISOString(), dsn: cfg.rawDsn || undefined, sdk: { name: "bugfinder.mini", version: "2.0.0" } },
      [[
        { type: "log", item_count: batch.length, content_type: "application/vnd.sentry.items.log+json" },
        { version: 2, items: batch }
      ]],
      Boolean(preferBeacon)
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

  function installFetchCapture() {
    if (cfg.fetchWrapped || !origFetch || typeof root.fetch !== "function") return;
    cfg.fetchWrapped = true;
    root.fetch = function (input, initOpts) {
      var urlStr =
        typeof input === "string"
          ? input
          : input && typeof input.url === "string"
          ? input.url
          : input && typeof input.href === "string"
          ? input.href
          : formatUnknown(input);
      if (isOwnTelemetryUrl(urlStr)) {
        return origFetch.apply(root, arguments);
      }
      var method = ((initOpts && initOpts.method) || (input && input.method) || "GET").toUpperCase();
      var safePath = sanitizeUrl(urlStr).split("?")[0].slice(0, 200);
      var callArgs = arguments;
      if (cfg.tracePropagation && cfg.traceId && typeof location !== "undefined") {
        try {
          var targetOrigin = new URL(urlStr, location.href).origin;
          if (targetOrigin === location.origin) {
            var nextInit = initOpts ? Object.assign({}, initOpts) : {};
            var h = nextInit.headers;
            var hasTp = false;
            if (typeof Headers !== "undefined" && h instanceof Headers) {
              hasTp = h.has("traceparent");
              if (!hasTp) h.set("traceparent", "00-" + cfg.traceId + "-" + uuidHex().slice(0, 16) + "-01");
            } else {
              var hdrObj = Object.assign({}, h || {});
              for (var hk in hdrObj) {
                if (String(hk).toLowerCase() === "traceparent") hasTp = true;
              }
              if (!hasTp) hdrObj.traceparent = "00-" + cfg.traceId + "-" + uuidHex().slice(0, 16) + "-01";
              nextInit.headers = hdrObj;
            }
            callArgs = [input, nextInit];
          }
        } catch (_) {}
      }
      var startedAt = nowMs();
      return origFetch.apply(root, callArgs).then(
        function (resp) {
          var dur = Math.max(0, Math.round(nowMs() - startedAt));
          var st = resp ? resp.status : 0;
          addBreadcrumb({
            type: "http",
            category: "fetch",
            level: st >= 500 ? "error" : "info",
            data: { status_code: st, duration_ms: dur, method: method },
            message: method + " " + safePath + " -> " + st + " (" + dur + " ms)"
          });
          if (resp && resp.status >= 500) {
            captureException(new Error("HTTP " + resp.status + " on " + method + " " + safePath), {
              http_status: resp.status,
              http_method: method,
              duration_ms: dur
            });
          } else if (dur > cfg.slowMs && !isStreamingUrl(safePath)) {
            var ctype = "";
            try { ctype = resp && resp.headers && resp.headers.get("content-type") || ""; } catch (_) {}
            if (String(ctype).toLowerCase().indexOf("text/event-stream") === -1) {
              captureMessage("Slow API request (" + dur + " ms): " + method + " " + safePath, "warning", {
                url: safePath,
                method: method,
                status_code: st,
                duration_ms: dur,
                slow_threshold_ms: cfg.slowMs
              });
            }
          }
          return resp;
        },
        function (err) {
          if (err && err.name === "AbortError") {
            throw err;
          }
          var dur = Math.max(0, Math.round(nowMs() - startedAt));
          addBreadcrumb({
            type: "http",
            category: "fetch",
            level: "error",
            data: { duration_ms: dur, method: method },
            message: method + " " + safePath + " failed (" + dur + " ms)"
          });
          captureException(err instanceof Error ? err : new Error("Network failure on " + method + " " + safePath), {
            http_method: method,
            duration_ms: dur
          });
          throw err;
        }
      );
    };
  }

  function installXhrCapture() {
    if (cfg.xhrWrapped || typeof root.XMLHttpRequest !== "function" || !root.XMLHttpRequest.prototype) return;
    cfg.xhrWrapped = true;
    var proto = root.XMLHttpRequest.prototype;
    var origOpen = proto.open;
    var origSend = proto.send;
    if (typeof origOpen !== "function" || typeof origSend !== "function") return;

    proto.open = function (method, url) {
      try {
        this._bfMethod = String(method || "GET").toUpperCase();
        this._bfUrl = url && typeof url.href === "string" ? url.href : String(url || "");
      } catch (_) {}
      return origOpen.apply(this, arguments);
    };

    proto.send = function () {
      try {
        var self = this;
        var rawUrl = self._bfUrl || "";
        if (rawUrl && !isOwnTelemetryUrl(rawUrl) && !self._bfBound && typeof self.addEventListener === "function") {
          self._bfBound = true;
          var method = self._bfMethod || "GET";
          var safePath = sanitizeUrl(rawUrl).split("?")[0].slice(0, 200);
          var xhrStartedAt = 0;
          self.addEventListener("loadstart", function () {
            xhrStartedAt = nowMs();
          });
          self.addEventListener("load", function () {
            var dur = xhrStartedAt ? Math.max(0, Math.round(nowMs() - xhrStartedAt)) : 0;
            addBreadcrumb({
              type: "http",
              category: "xhr",
              level: self.status >= 500 ? "error" : "info",
              data: { status_code: self.status || 0, duration_ms: dur, method: method },
              message: method + " " + safePath + " -> " + (self.status || 0) + " (" + dur + " ms)"
            });
            if (self.status >= 500) {
              captureException(new Error("XHR HTTP " + self.status + " on " + method + " " + safePath), {
                http_status: self.status,
                http_method: method,
                duration_ms: dur
              });
            } else if (dur > cfg.slowMs && !isStreamingUrl(safePath)) {
              captureMessage("Slow API request (" + dur + " ms): " + method + " " + safePath, "warning", {
                url: safePath,
                method: method,
                status_code: self.status || 0,
                duration_ms: dur,
                slow_threshold_ms: cfg.slowMs
              });
            }
          });
          self.addEventListener("error", function () {
            var dur = xhrStartedAt ? Math.max(0, Math.round(nowMs() - xhrStartedAt)) : 0;
            addBreadcrumb({ type: "http", category: "xhr", level: "error", data: { duration_ms: dur, method: method }, message: method + " " + safePath + " failed (" + dur + " ms)" });
            captureException(new Error("XHR network error on " + method + " " + safePath), { http_method: method, duration_ms: dur });
          });
          self.addEventListener("timeout", function () {
            var dur = xhrStartedAt ? Math.max(0, Math.round(nowMs() - xhrStartedAt)) : 0;
            addBreadcrumb({ type: "http", category: "xhr", level: "error", data: { duration_ms: dur, method: method }, message: method + " " + safePath + " timed out (" + dur + " ms)" });
            captureException(new Error("XHR timeout on " + method + " " + safePath), { http_method: method, duration_ms: dur });
          });
        }
      } catch (_) {}
      return origSend.apply(this, arguments);
    };
  }

  function installConsoleCapture(modeStr) {
    if (cfg.consoleWrapped || typeof console === "undefined") return;
    cfg.consoleWrapped = true;
    var parts = String(modeStr || "").toLowerCase().split(",");
    var capWarn = parts.indexOf("warn") !== -1;
    var origErr = typeof console.error === "function" ? console.error.bind(console) : null;
    var origWarn = capWarn && typeof console.warn === "function" ? console.warn.bind(console) : null;
    function formatArgs(args) {
      var out = [];
      for (var i = 0; i < args.length; i++) {
        out.push(formatUnknown(args[i]));
      }
      return out.join(" ").slice(0, 800);
    }
    if (origErr) {
      console.error = function () {
        if (!cfg.inConsole) {
          cfg.inConsole = true;
          try { pushLog("error", formatArgs(arguments), { source: "console.error" }); } catch (_) {}
          cfg.inConsole = false;
        }
        return origErr.apply(console, arguments);
      };
    }
    if (origWarn) {
      console.warn = function () {
        if (!cfg.inConsole) {
          cfg.inConsole = true;
          try { pushLog("warn", formatArgs(arguments), { source: "console.warn" }); } catch (_) {}
          cfg.inConsole = false;
        }
        return origWarn.apply(console, arguments);
      };
    }
  }

  function init(options) {
    options = options || {};
    cfg.rawDsn = options.dsn || "";
    cfg.shieldEndpoint = options.shieldEndpoint || "";
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
    cfg.tracePropagation = Boolean(options.tracePropagation);
    if (cfg.tracePropagation && !cfg.traceId) {
      cfg.traceId = uuidHex();
    }
    if (options.slowThresholdMs && Number(options.slowThresholdMs) >= 500) {
      cfg.slowMs = Number(options.slowThresholdMs);
    }

    if (cfg.release && !cfg.sessionPinged && cfg.endpoint) {
      cfg.sessionPinged = true;
      sendEnvelope(
        { sent_at: new Date().toISOString(), dsn: cfg.rawDsn || undefined, sdk: { name: "bugfinder.mini", version: "2.0.0" } },
        [[{ type: "session" }, { init: true, status: "ok", errors: 0, sid: uuidHex(), attrs: { release: cfg.release, environment: cfg.environment } }]],
        true
      );
    }

    if (options.captureFetch) installFetchCapture();
    if (options.captureFetch || options.captureXhr) installXhrCapture();
    if (options.captureConsole) installConsoleCapture(options.captureConsole);

    if (typeof window !== "undefined" && !cfg.initialized) {
      cfg.initialized = true;
      window.addEventListener("error", function (ev) {
        if (ev && ev.error) {
          captureException(ev.error);
        } else if (ev && ev.message) {
          captureMessage(ev.message, "error");
        } else if (ev && ev.target && ev.target !== root && ev.target.tagName) {
          var el = ev.target;
          var resUrl = el.src || el.href || el.currentSrc || "";
          if (resUrl && !isOwnTelemetryUrl(resUrl)) {
            captureMessage(
              "Resource load failed: <" + el.tagName.toLowerCase() + "> " + String(resUrl).slice(0, 240),
              "error",
              { resource_tag: el.tagName.toLowerCase(), resource_url: String(resUrl).slice(0, 500) }
            );
          }
        }
      }, true);
      window.addEventListener("unhandledrejection", function (ev) {
        var reason = ev && ev.reason;
        if (reason instanceof Error) {
          captureException(reason);
        } else {
          captureException(new Error(formatUnknown(reason) || "Unhandled rejection"));
        }
      });
      window.addEventListener("securitypolicyviolation", function (ev) {
        if (!ev) return;
        var dir = ev.effectiveDirective || ev.violatedDirective || "csp";
        var blocked = ev.blockedURI || "inline";
        captureMessage("CSP Violation (" + dir + "): " + blocked, "warning", {
          violated_directive: dir,
          blocked_uri: String(blocked).slice(0, 500),
          source_file: ev.sourceFile || undefined,
          line_number: ev.lineNumber || undefined
        });
      });
      var clickHist = [];
      window.addEventListener("click", function (ev) {
        var t = ev && ev.target;
        if (!t || !t.tagName) return;
        var sel = t.tagName.toLowerCase() + (t.id ? "#" + t.id : "");
        addBreadcrumb({
          type: "ui",
          category: "ui.click",
          message: sel
        });
        try {
          var interactive = typeof t.closest === "function"
            ? t.closest("button,a,[role='button']")
            : null;
          if (interactive && !interactive.closest("[data-private],input,textarea,select")) {
            var iTag = interactive.tagName ? interactive.tagName.toLowerCase() : "el";
            var actionAttr = interactive.getAttribute("data-action");
            var iSel = iTag + (interactive.id ? "#" + interactive.id : "") + (actionAttr ? "[data-action=" + actionAttr.slice(0, 32) + "]" : "");
            var nowTs = Date.now();
            clickHist = clickHist.filter(function (c) { return nowTs - c.ts <= 1200; });
            clickHist.push({ sel: iSel, ts: nowTs });
            var sameCount = 0;
            for (var ci = 0; ci < clickHist.length; ci++) {
              if (clickHist[ci].sel === iSel) sameCount++;
            }
            if (sameCount >= 4) {
              clickHist = [];
              captureMessage("Rage click on " + iSel, "warning", {
                target_selector: iSel,
                click_count: sameCount,
                window_ms: 1200
              });
            }
          }
        } catch (_) {}
      }, true);
      try {
        if (typeof PerformanceObserver === "function") {
          var latestLcp = 0;
          var clsValue = 0;
          var vitalsReported = false;
          var lcpObs = new PerformanceObserver(function (list) {
            var entries = list.getEntries();
            if (entries && entries.length) {
              latestLcp = Math.round(entries[entries.length - 1].startTime || 0);
            }
          });
          lcpObs.observe({ type: "largest-contentful-paint", buffered: true });
          var clsObs = new PerformanceObserver(function (list) {
            var entries = list.getEntries();
            for (var ei = 0; ei < entries.length; ei++) {
              if (!entries[ei].hadRecentInput) {
                clsValue += entries[ei].value || 0;
              }
            }
          });
          clsObs.observe({ type: "layout-shift", buffered: true });
          var flushVitals = function () {
            if (vitalsReported) return;
            vitalsReported = true;
            if (latestLcp > 4000) {
              captureMessage("Poor Web Vital: LCP " + latestLcp + " ms", "warning", {
                metric: "LCP",
                value_ms: latestLcp,
                threshold_ms: 4000
              });
            }
            if (clsValue > 0.25) {
              captureMessage("Poor Web Vital: CLS " + clsValue.toFixed(3), "warning", {
                metric: "CLS",
                value: Number(clsValue.toFixed(3)),
                threshold: 0.25
              });
            }
          };
          window.addEventListener("pagehide", flushVitals);
        }
      } catch (_) {}
      window.addEventListener("pagehide", function () { flushLogs(true); });
      if (typeof document !== "undefined" && typeof document.addEventListener === "function") {
        document.addEventListener("visibilitychange", function () {
          if (document.visibilityState === "hidden") {
            flushLogs(true);
          }
        });
      }
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

  // Zero-inline 1-tag auto-boot via <script src=".../sdk/bugfinder-mini.js" data-dsn="..." async>
  try {
    if (curScript && curScript.dataset) {
      var ds = curScript.dataset;
      if (ds.dsn || ds.tunnel) {
        var capFetch = ds.captureFetch === "true";
        init({
          dsn: ds.dsn || "",
          tunnel: ds.tunnel || "",
          shieldEndpoint: ds.shieldEndpoint || "",
          environment: ds.env || "production",
          release: ds.release || "",
          slowThresholdMs: ds.slowMs ? Number(ds.slowMs) : 5000,
          tracePropagation: ds.tracePropagation === "true",
          captureFetch: capFetch,
          captureConsole: ds.captureConsole || ""
        });
        var shieldMode = ds.shield || "";
        if (
          (shieldMode === "detect" || shieldMode === "defend" || shieldMode === "lockdown") &&
          curScript.src &&
          typeof document !== "undefined"
        ) {
          var baseHref = typeof location !== "undefined" && location.href ? location.href : undefined;
          var scriptUrl = new URL(curScript.src, baseHref);
          var shieldSrc = ds.shieldSrc || "/sdk/bugfinder-shield.js";
          var resolvedShieldUrl = new URL(shieldSrc, scriptUrl.toString());
          if (resolvedShieldUrl.origin === scriptUrl.origin) {
            var sTag = document.createElement("script");
            sTag.src = resolvedShieldUrl.toString();
            sTag.async = true;
            if (curScript.nonce) sTag.nonce = curScript.nonce;
            if (curScript.crossOrigin) sTag.crossOrigin = "anonymous";
            if (ds.shieldSri) sTag.integrity = ds.shieldSri;
            sTag.onload = function () {
              if (root.BugFinderShield && typeof root.BugFinderShield.init === "function") {
                var shieldOpts = { mode: shieldMode, allowFetchPatching: capFetch };
                if (ds.shieldEndpoint) {
                  shieldOpts.endpoint = ds.shieldEndpoint;
                } else if (ds.dsn) {
                  shieldOpts.dsn = ds.dsn;
                }
                root.BugFinderShield.init(shieldOpts);
              }
            };
            (document.head || document.documentElement).appendChild(sTag);
          }
        }
      }
    }
  } catch (_) {}
})(typeof globalThis !== "undefined" ? globalThis : window);
