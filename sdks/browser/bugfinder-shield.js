(function (root) {
  "use strict";

  var origFetch = typeof root.fetch === "function" ? root.fetch : null;
  var origBeacon = typeof navigator !== "undefined" && typeof navigator.sendBeacon === "function"
    ? navigator.sendBeacon.bind(navigator)
    : null;
  var origToString = Function.prototype.toString;
  var origXhrOpen = typeof XMLHttpRequest !== "undefined" && XMLHttpRequest.prototype
    ? XMLHttpRequest.prototype.open
    : null;
  var origWs = typeof root.WebSocket === "function" ? root.WebSocket : null;

  var WEIGHTS = {
    runtime_debugger_attached: 80,
    canary_route_hit: 75,
    injection_probe: 75,
    honeypot_access: 70,
    sourcemap_harvest: 65,
    idor_or_enum_burst: 65,
    secret_leak: 60,
    cdp_automation: 50,
    webdriver_detected: 45,
    runtime_hook_tamper: 40,
    csp_script_tamper: 40,
    dom_script_injection: 35
  };

  var cfg = {
    initialized: false,
    endpoint: "",
    dsnKey: "",
    mode: "detect",
    threshold: 80,
    allowLocalhost: false,
    allowFetchPatching: false,
    monitorScripts: false,
    allowedScriptOrigins: [],
    canaryGlobals: ["__BF_INTERNAL_SECRETS__"],
    clearStorageKeys: [],
    sessionId: "",
    onThreat: null,
    refFetchAtInit: null,
    refXhrAtInit: null,
    refWsAtInit: null,
    sentSigs: Object.create(null),
    lockedDown: false,
    timer: null,
    observer: null
  };

  function parseShieldEndpoint(dsn) {
    try {
      var u = new URL(dsn);
      var key = u.username;
      var pid = u.pathname.replace(/^\/+|\/+$/g, "").split("/").pop();
      if (!key || !pid) return null;
      return {
        endpoint: u.protocol + "//" + u.host + "/api/" + encodeURIComponent(pid) + "/shield/",
        dsnKey: key
      };
    } catch (_) {
      return null;
    }
  }

  function isLocalHostEnv() {
    try {
      var h = root.location && root.location.hostname ? String(root.location.hostname).toLowerCase() : "";
      return h === "localhost" || h === "127.0.0.1" || h === "::1" || h === "[::1]";
    } catch (_) {
      return false;
    }
  }

  function randomSessionId() {
    var cryptoObj = root.crypto || root.msCrypto;
    if (cryptoObj && typeof cryptoObj.getRandomValues === "function") {
      var bytes = new Uint8Array(12);
      cryptoObj.getRandomValues(bytes);
      var out = "";
      for (var i = 0; i < bytes.length; i++) {
        out += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
      }
      return out;
    }
    var s = "";
    for (var j = 0; j < 24; j++) s += Math.floor(Math.random() * 16).toString(16);
    return s;
  }

  function sendPayload(bodyObj) {
    if (!cfg.endpoint) return;
    var url = cfg.endpoint + (cfg.dsnKey ? "?sentry_key=" + encodeURIComponent(cfg.dsnKey) : "");
    var raw = JSON.stringify(bodyObj);
    try {
      if (origBeacon && raw.length <= 60000) {
        var payload = typeof Blob === "function"
          ? new Blob([raw], { type: "text/plain;charset=UTF-8" })
          : raw;
        if (origBeacon(url, payload)) return;
      }
      if (origFetch) {
        origFetch.call(root, url, {
          method: "POST",
          mode: "cors",
          credentials: "omit",
          body: raw,
          keepalive: raw.length <= 60000,
          headers: { "Content-Type": "text/plain;charset=UTF-8" }
        }).catch(function () {});
      }
    } catch (_) {}
  }

  function scoreLocal(signals) {
    var sum = 0;
    var seen = Object.create(null);
    for (var i = 0; i < signals.length; i++) {
      var k = signals[i];
      if (!seen[k] && WEIGHTS[k]) {
        seen[k] = true;
        sum += WEIGHTS[k];
      }
    }
    return sum > 100 ? 100 : sum;
  }

  function clearConfiguredStorage() {
    for (var i = 0; i < cfg.clearStorageKeys.length; i++) {
      var k = cfg.clearStorageKeys[i];
      try { if (typeof localStorage !== "undefined") localStorage.removeItem(k); } catch (_) {}
      try { if (typeof sessionStorage !== "undefined") sessionStorage.removeItem(k); } catch (_) {}
    }
  }

  function emitThreat(signals, details) {
    if (!signals || !signals.length) return null;
    var sorted = signals.slice().sort();
    var sigKey = sorted.join(",");
    var now = Date.now();
    if (cfg.sentSigs[sigKey] && now - cfg.sentSigs[sigKey] < 30000) {
      return null;
    }
    cfg.sentSigs[sigKey] = now;

    var score = scoreLocal(sorted);
    var path = "";
    try { path = root.location && root.location.pathname ? String(root.location.pathname) : ""; } catch (_) {}

    if (score >= cfg.threshold && (cfg.mode === "defend" || cfg.mode === "lockdown")) {
      clearConfiguredStorage();
      if (cfg.mode === "lockdown") cfg.lockedDown = true;
    }

    var report = {
      signals: sorted,
      risk_score: score,
      mode: cfg.mode,
      locked_down: cfg.lockedDown,
      session_id: cfg.sessionId,
      path: path,
      details: details || {}
    };

    if (typeof cfg.onThreat === "function") {
      try { cfg.onThreat(report); } catch (_) {}
    }
    sendPayload({
      signals: sorted,
      session_id: cfg.sessionId,
      path: path,
      source: "browser",
      details: details || {}
    });
    return report;
  }

  function checkNow() {
    if (!cfg.initialized) return null;
    if (isLocalHostEnv() && !cfg.allowLocalhost) return null;

    var detected = [];
    var details = {};

    try {
      var ua = typeof navigator !== "undefined" && navigator.userAgent ? String(navigator.userAgent) : "";
      if ((typeof navigator !== "undefined" && navigator.webdriver === true) || /HeadlessChrome|PhantomJS/i.test(ua)) {
        detected.push("webdriver_detected");
      }
    } catch (_) {}

    try {
      if (
        "__playwright__binding__" in root ||
        "__pwInitScripts" in root ||
        "_phantom" in root ||
        "callPhantom" in root ||
        "__nightmare" in root
      ) {
        detected.push("cdp_automation");
      } else {
        var keys = Object.keys(root);
        for (var i = 0; i < keys.length; i++) {
          if (keys[i].indexOf("$cdc_") === 0 || keys[i].indexOf("cdc_") === 0) {
            detected.push("cdp_automation");
            details.cdp_prop = keys[i];
            break;
          }
        }
      }
    } catch (_) {}

    try {
      if (!cfg.allowFetchPatching && cfg.refFetchAtInit && root.fetch !== cfg.refFetchAtInit) {
        detected.push("runtime_hook_tamper");
        details.hook = "fetch";
      } else if (
        !cfg.allowFetchPatching &&
        cfg.refXhrAtInit &&
        typeof XMLHttpRequest !== "undefined" &&
        XMLHttpRequest.prototype &&
        XMLHttpRequest.prototype.open !== cfg.refXhrAtInit
      ) {
        detected.push("runtime_hook_tamper");
        details.hook = "xhr";
      } else if (cfg.refWsAtInit && root.WebSocket !== cfg.refWsAtInit) {
        detected.push("runtime_hook_tamper");
        details.hook = "websocket";
      } else if (origToString.call(Function.prototype.toString).indexOf("[native code]") === -1) {
        detected.push("runtime_hook_tamper");
        details.hook = "Function.prototype.toString";
      }
    } catch (_) {}

    return detected.length ? emitThreat(detected, details) : null;
  }

  function installCanaryTraps() {
    for (var i = 0; i < cfg.canaryGlobals.length; i++) {
      (function (prop) {
        if (!prop || prop in root) return;
        try {
          Object.defineProperty(root, prop, {
            configurable: false,
            enumerable: false,
            get: function () {
              emitThreat(["honeypot_access"], { canary_global: prop });
              return undefined;
            }
          });
        } catch (_) {}
      })(cfg.canaryGlobals[i]);
    }
  }

  function installScriptObserver() {
    if (!cfg.monitorScripts || typeof MutationObserver === "undefined" || typeof document === "undefined") return;
    var ownOrigin = "";
    try { ownOrigin = root.location && root.location.origin ? root.location.origin : ""; } catch (_) {}
    try {
      var obs = new MutationObserver(function (mutations) {
        for (var m = 0; m < mutations.length; m++) {
          var added = mutations[m].addedNodes || [];
          for (var n = 0; n < added.length; n++) {
            var el = added[n];
            if (!el || el.tagName !== "SCRIPT" || !el.src) continue;
            try {
              var u = new URL(el.src, ownOrigin || "http://localhost");
              if (u.protocol !== "http:" && u.protocol !== "https:") continue;
              if (ownOrigin && u.origin === ownOrigin) continue;
              if (cfg.allowedScriptOrigins.indexOf(u.origin) !== -1) continue;
              emitThreat(["dom_script_injection"], { script_origin: u.origin });
            } catch (_) {}
          }
        }
      });
      if (document.documentElement) {
        cfg.observer = obs;
        obs.observe(document.documentElement, { childList: true, subtree: true });
      }
    } catch (_) {}
  }

  function init(options) {
    options = options || {};
    if (cfg.initialized) return;
    cfg.initialized = true;

    if (options.endpoint) {
      cfg.endpoint = options.endpoint;
      cfg.dsnKey = options.dsnKey || "";
    } else if (options.dsn) {
      var parsed = parseShieldEndpoint(options.dsn);
      if (parsed) {
        cfg.endpoint = parsed.endpoint;
        cfg.dsnKey = parsed.dsnKey;
      }
    }

    cfg.mode = options.mode || "detect";
    cfg.threshold = typeof options.threshold === "number" ? options.threshold : 80;
    cfg.allowLocalhost = Boolean(options.allowLocalhost);
    cfg.allowFetchPatching = Boolean(options.allowFetchPatching);
    cfg.monitorScripts = Boolean(options.monitorScripts);
    cfg.allowedScriptOrigins = Array.isArray(options.allowedScriptOrigins) ? options.allowedScriptOrigins : [];
    cfg.canaryGlobals = Array.isArray(options.canaryGlobals) ? options.canaryGlobals : ["__BF_INTERNAL_SECRETS__"];
    cfg.clearStorageKeys = Array.isArray(options.clearStorageKeys) ? options.clearStorageKeys : [];
    cfg.sessionId = options.sessionId || randomSessionId();
    cfg.onThreat = typeof options.onThreat === "function" ? options.onThreat : null;

    // Record wrapper state at init time so legitimate pre-loaded wrappers (Zone.js/Sentry) are not flagged
    cfg.refFetchAtInit = root.fetch || null;
    cfg.refXhrAtInit = typeof XMLHttpRequest !== "undefined" && XMLHttpRequest.prototype ? XMLHttpRequest.prototype.open : null;
    cfg.refWsAtInit = root.WebSocket || null;

    if (isLocalHostEnv() && !cfg.allowLocalhost) {
      return;
    }

    installCanaryTraps();
    installScriptObserver();
    checkNow();

    if (typeof setInterval === "function") {
      var t = setInterval(function () {
        if (typeof document !== "undefined" && document.visibilityState === "hidden") return;
        checkNow();
      }, 5000);
      if (t && typeof t.unref === "function") t.unref();
      cfg.timer = t;
    }
  }

  function destroy() {
    if (cfg.timer) {
      try { clearInterval(cfg.timer); } catch (_) {}
      cfg.timer = null;
    }
    if (cfg.observer) {
      try { cfg.observer.disconnect(); } catch (_) {}
      cfg.observer = null;
    }
    cfg.initialized = false;
    cfg.lockedDown = false;
    cfg.sentSigs = Object.create(null);
  }

  var api = {
    init: init,
    scan: checkNow,
    report: emitThreat,
    destroy: destroy,
    isLockedDown: function () { return cfg.lockedDown; }
  };
  try {
    Object.freeze(api);
  } catch (_) {}

  root.BugFinderShield = api;
})(typeof globalThis !== "undefined" ? globalThis : window);
