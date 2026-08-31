(function () {
  "use strict";

  var LS = {
    get: function (k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
  };

  var savedTheme = LS.get("flop-theme");
  if (savedTheme) { document.documentElement.setAttribute("data-theme", savedTheme); }
  window.toggleTheme = function () {
    var stamp = document.documentElement.getAttribute("data-theme");
    var effective = stamp ||
      (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    setTheme(effective === "dark" ? "light" : "dark");
  };

  function setTheme(mode) {
    if (mode === "system") {
      document.documentElement.removeAttribute("data-theme");
      try { localStorage.removeItem("flop-theme"); } catch (e) {}
    } else {
      document.documentElement.setAttribute("data-theme", mode);
      LS.set("flop-theme", mode);
    }
    reflectTheme();
  }
  function reflectTheme() {
    var cur = LS.get("flop-theme") || "system";
    var picks = document.getElementById("themepicks");
    if (picks) {
      picks.querySelectorAll("button").forEach(function (b) {
        b.classList.toggle("on", b.getAttribute("data-theme") === cur);
      });
    }
  }

  var toastEl = document.getElementById("toast"), toastT;
  window.toast = function (msg) {
    toastEl.textContent = msg; toastEl.classList.add("show");
    clearTimeout(toastT); toastT = setTimeout(function () { toastEl.classList.remove("show"); }, 2100);
  };

  function api(method, path, body) {
    var opts = { method: method, headers: {} };
    if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
    return fetch(path, opts).then(function (r) {
      return r.json().then(function (data) { return { ok: r.ok, status: r.status, data: data }; });
    });
  }

  function shortDid(full) {
    if (!full) return "…";
    var mb = full.indexOf("did:key:") === 0 ? full.slice(8) : full;
    if (mb.length <= 14) return mb;
    return mb.slice(0, 8) + "…" + mb.slice(-4);
  }

  var lastGenerated = null;

  function show(id) {
    ["s1", "s-create", "s-import", "s-backup", "s-fork", "s-fork-a"].forEach(function (s) {
      document.getElementById(s).classList.toggle("hidden", s !== id);
    });
  }
  function setStep(n) {
    var el = document.getElementById("steps").children;
    for (var i = 0; i < el.length; i++) { el[i].classList.toggle("on", i < n); }
  }
  window.go = function (which) {
    if (which === "create") { show("s-create"); setStep(2); }
    else { show("s-import"); setStep(2); }
  };
  window.back = function () { show("s1"); setStep(1); };

  function showSetup() {
    document.getElementById("app").classList.add("hidden");
    document.getElementById("setup").classList.remove("hidden");
    window.scrollTo(0, 0);
  }
  function showFork() { showSetup(); show("s-fork"); setStep(3); }

  function routeIn(status) {
    var p = status && status.setup_path;
    if (p === "B") { enterApp(status, "agent"); return; }
    if (p === "C") { enterApp(status); return; }
    if (p === "A") {
      if (status.deploy === "live") { enterApp(status); return; }
      showSetup(); show("s-fork-a"); setStep(3); initDeployScreen(); return;
    }
    showFork();
  }

  window.chooseFork = function (which) {
    api("POST", "/api/onboarding/choose", { path: which })
      .then(function (res) {
        if (!res.ok) { toast("Could not save your choice; try again"); return; }
        if (which === "A") { show("s-fork-a"); setStep(3); initDeployScreen(); return; }
        return api("GET", "/api/status").then(function (r) {
          if (!r.ok) { toast("Saved, but the server did not respond; reload to continue"); return; }
          routeIn(r.data || {});
        });
      })
      .catch(function () { toast("Could not save your choice; try again"); });
  };

  window.backToFork = function () {
    clearDepTimers();
    api("POST", "/api/onboarding/reset", {}).then(showFork).catch(showFork);
  };

  var selectedWake = 15, depPollTimer = null, depConnTimer = null, connAttempts = 0;
  function clearDepTimers() {
    if (depPollTimer) { clearTimeout(depPollTimer); depPollTimer = null; }
    if (depConnTimer) { clearTimeout(depConnTimer); depConnTimer = null; }
  }
  var WAKE_HINT = {
    1: "Every minute is lively, but it uses the free daily allowance in about 4 hours; a paid plan runs it all day.",
    5: "Every 5 minutes: livelier, still comfortably within the free tier.",
    10: "Every 10 minutes: comfortable, well within free.",
    15: "At 15 minutes it stays comfortably within Cloudflare's free tier for normal use. Recommended.",
    30: "Every 30 minutes: very light.",
    60: "Once an hour: the lightest touch."
  };
  function renderWake() {
    var box = document.getElementById("dep-wake");
    if (!box) return;
    box.textContent = "";
    [1, 5, 10, 15, 30, 60].forEach(function (m) {
      var b = el("button", "btn sm" + (m === selectedWake ? " on" : ""), m >= 60 ? "1 hr" : m + " min");
      b.type = "button";
      b.onclick = function () { selectedWake = m; renderWake(); updateCostHint(); };
      box.appendChild(b);
    });
  }
  function updateCostHint() {
    var h = document.getElementById("dep-cost-hint");
    if (h) h.textContent = WAKE_HINT[selectedWake] || "";
  }
  function initDeployScreen() {
    clearDepTimers();
    selectedWake = 15; renderWake(); updateCostHint();
    var setHidden = function (id, hide) { var e = document.getElementById(id); if (e) e.classList.toggle("hidden", hide); };
    setHidden("dep-connect", false); setHidden("dep-form", true);
    setHidden("dep-progress", true); setHidden("dep-done", true); setHidden("dep-failed", true);
    var st = document.getElementById("dep-conn-state"); if (st) st.textContent = "checking…";
    api("GET", "/api/deploy/connection").then(function (r) {
      var ok = r.ok && r.data && r.data.connected;
      if (st) st.textContent = ok ? "Connected ✓" : "";
      setHidden("dep-form", !ok);
      var btn = document.getElementById("dep-connect-btn"); if (btn && ok) btn.textContent = "Reconnect";
    }).catch(function () { if (st) st.textContent = ""; });
  }
  window.deployConnect = function () {
    var st = document.getElementById("dep-conn-state");
    if (st) st.textContent = "Opening the browser…";
    clearDepTimers(); connAttempts = 0;
    api("POST", "/api/deploy/login", {}).then(function () { pollConn(); })
      .catch(function () { if (st) st.textContent = "Could not start sign-in; try again"; });
  };
  function pollConn() {
    api("GET", "/api/deploy/connection").then(function (r) {
      var st = document.getElementById("dep-conn-state");
      if (r.ok && r.data && r.data.connected) {
        connAttempts = 0;
        if (st) st.textContent = "Connected ✓";
        document.getElementById("dep-form").classList.remove("hidden");
        var btn = document.getElementById("dep-connect-btn"); if (btn) btn.textContent = "Reconnect";
        return;
      }
      if (++connAttempts > 150) {
        if (st) st.textContent = "That took too long. Click Connect Cloudflare to try again.";
        return;
      }
      if (st) st.textContent = "Waiting for you to sign in…";
      depConnTimer = setTimeout(pollConn, 2000);
    }).catch(function () {
      if (++connAttempts > 150) { return; }
      depConnTimer = setTimeout(pollConn, 2500);
    });
  }
  window.deployStart = function () {
    var name = (document.getElementById("dep-name").value || "").trim();
    var model = document.getElementById("dep-model").value;
    if (!name) { toast("Give your agent a name"); return; }
    api("POST", "/api/deploy/start", { agent_name: name, model: model, wake: selectedWake }).then(function (r) {
      if (!r.ok) { toast((r.data && r.data.error) || "Could not start the deploy"); return; }
      document.getElementById("dep-connect").classList.add("hidden");
      document.getElementById("dep-form").classList.add("hidden");
      document.getElementById("dep-progress").classList.remove("hidden");
      pollDeploy();
    }).catch(function () { toast("Could not start the deploy"); });
  };
  function renderSteps(steps) {
    var box = document.getElementById("dep-steps");
    if (!box) return;
    var glyph = { pending: "•", running: "…", ok: "✓", failed: "✗" };
    box.textContent = "";
    steps.forEach(function (s) {
      var row = el("div", "ds " + s.status);
      row.appendChild(el("span", "glyph", glyph[s.status] || "•"));
      var d = el("div");
      d.appendChild(el("b", null, s.title));
      if (s.detail) d.appendChild(el("p", null, s.detail));
      row.appendChild(d);
      box.appendChild(row);
    });
  }
  function pollDeploy() {
    api("GET", "/api/deploy/status").then(function (r) {
      var d = r.data || {};
      renderSteps(d.steps || []);
      if (d.overall === "live") { document.getElementById("dep-done").classList.remove("hidden"); return; }
      if (d.overall === "failed") {
        var failed = (d.steps || []).filter(function (s) { return s.status === "failed"; })[0];
        var msg = document.getElementById("dep-fail-msg");
        if (msg) msg.textContent = failed ? (failed.title + ": " + (failed.detail || "it did not complete")) : "The deploy did not complete.";
        document.getElementById("dep-failed").classList.remove("hidden");
        return;
      }
      depPollTimer = setTimeout(pollDeploy, 1200);
    }).catch(function () { depPollTimer = setTimeout(pollDeploy, 2000); });
  }
  window.deployRetry = function () {
    document.getElementById("dep-progress").classList.add("hidden");
    document.getElementById("dep-failed").classList.add("hidden");
    document.getElementById("dep-connect").classList.remove("hidden");
    initDeployScreen();
  };
  window.enterAppNow = function () {
    api("GET", "/api/status").then(function (r) { enterApp(r.data || {}); })
      .catch(function () { toast("The local server did not respond"); });
  };

  var selectedCostWake = 15;
  function renderCostWake(choices) {
    var box = document.getElementById("cost-wake");
    if (!box) return;
    box.textContent = "";
    (choices || [1, 5, 10, 15, 30, 60]).forEach(function (m) {
      var b = el("button", "btn sm" + (m === selectedCostWake ? " on" : ""), m >= 60 ? "1 hr" : m + " min");
      b.type = "button";
      b.onclick = function () { selectedCostWake = m; renderCostWake(choices); updateCostWakeHint(); };
      box.appendChild(b);
    });
  }
  function updateCostWakeHint() {
    var h = document.getElementById("cost-wake-hint");
    if (h) h.textContent = WAKE_HINT[selectedCostWake] || "";
  }
  function renderHealth(hh, targetId) {
    var b = document.getElementById(targetId || "cost-health");
    if (!b) return;
    hh = hh || { status: "unknown" };
    var m = hh.model ? " (" + hh.model + ")" : "";
    var cls = "banner", txt;
    if (hh.status === "ok") { cls += " good"; txt = "Model working" + m + (hh.detail ? " · " + hh.detail : ""); }
    else if (hh.status === "error") { cls += " err"; txt = "Model not responding" + m + " - pick another." + (hh.detail ? " " + hh.detail : ""); }
    else if (hh.status === "paused") { cls += " warn"; txt = "Paused" + (hh.detail ? " · " + hh.detail : ""); }
    else if (hh.status === "stale") { cls += " warn"; txt = hh.detail || "No recent report."; }
    else { cls += " warn"; txt = hh.detail || "Model health: not reported yet."; }
    b.className = cls; b.textContent = txt;
  }
  window.toggleCostCustom = function () {
    var on = document.getElementById("cost-custom-on").checked;
    document.getElementById("cost-custom").classList.toggle("hidden", !on);
    document.getElementById("cost-model").disabled = on;
  };
  window.toggleCostPw = function () {
    var e = document.getElementById("costpw");
    e.type = e.type === "password" ? "text" : "password";
  };
  function loadCost() {
    api("GET", "/api/cost").then(function (r) {
      var d = r.data || {};
      selectedCostWake = d.wake || 15;
      renderCostWake(d.wake_choices);
      updateCostWakeHint();
      var src = document.getElementById("cost-source");
      if (src) {
        if (d.source === "signed") {
          src.textContent = "Your signed setting" + (d.published === false ? ", not yet reached your agent." : ".");
        } else if (d.source === "deployed") {
          src.textContent = "Set when you deployed: " + (d.model || "") + ". Change it below.";
        } else {
          src.textContent = "No model set yet. Choose one below.";
        }
      }
      var sel = document.getElementById("cost-model");
      if (sel) {
        sel.textContent = "";
        var found = false;
        (d.model_choices || []).forEach(function (m) {
          var id = (typeof m === "string") ? m : m.id;
          var label = (typeof m === "string") ? m : (m.label || m.id);
          var o = el("option", null, label); o.value = id;
          if (id === d.model) { o.selected = true; found = true; }
          sel.appendChild(o);
        });
        if (!found && d.model) {                        // a custom model not in the list
          document.getElementById("cost-custom-on").checked = true;
          toggleCostCustom();
          document.getElementById("cost-custom").value = d.model;
        }
      }
      renderHealth(d.health);
    }).catch(function () {});
  }
  window.applyCost = function () {
    var custom = document.getElementById("cost-custom-on").checked;
    var model = custom ? (document.getElementById("cost-custom").value || "").trim()
                       : document.getElementById("cost-model").value;
    var pw = document.getElementById("costpw").value;
    if (!model) { toast("Choose or enter a model"); return; }
    if (!pw) { toast("Enter your passphrase to sign the setting"); return; }
    var st = document.getElementById("cost-state"); if (st) st.textContent = "Signing…";
    api("POST", "/api/cost/save", { model: model, wake: selectedCostWake, passphrase: pw }).then(function (r) {
      document.getElementById("costpw").value = "";
      if (!r.ok) { toast((r.data && r.data.error) || "Could not apply the setting"); if (st) st.textContent = ""; return; }
      if (st) st.textContent = r.data.published ? "Applied - your agent picks it up within a minute." : "Signed, but it did not reach the network; try again.";
      loadCost();
    }).catch(function () { document.getElementById("costpw").value = ""; toast("Could not apply the setting"); });
  };

  window.togglePw = function () {
    var el = document.getElementById("pw"), btn = document.getElementById("pwshow");
    var showing = el.type === "text";
    el.type = showing ? "password" : "text";
    btn.textContent = showing ? "Show" : "Hide";
  };

  window.genKey = function () {
    var b = new Uint8Array(18);
    (window.crypto || window.msCrypto).getRandomValues(b);
    var s = btoa(String.fromCharCode.apply(null, b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    lastGenerated = s;
    var el = document.getElementById("pw");
    el.value = s; el.type = "text";
    document.getElementById("pwshow").textContent = "Hide";
    toast("Generated a strong passphrase. Save it now, it is shown once.");
  };

  function toBackupStep(did) {
    document.getElementById("new-did").textContent = shortDid(did);
    var box = document.getElementById("genpw-box");
    if (lastGenerated && document.getElementById("pw").value === lastGenerated) {
      box.textContent = "passphrase (save this): " + lastGenerated;
      box.classList.remove("hidden");
    } else {
      box.classList.add("hidden");
    }
    show("s-backup"); setStep(3);
  }

  window.createKey = function () {
    var pw = document.getElementById("pw").value || "";
    if (pw.length < 12) { toast("Passphrase needs at least 12 characters"); return; }
    api("POST", "/api/key/create", { passphrase: pw }).then(function (res) {
      if (!res.ok || !res.data.ok) { toast(res.data.error || "Could not create the key"); return; }
      toBackupStep(res.data.did);
    }).catch(function () { toast("The local server did not respond"); });
  };

  window.importKey = function () {
    var fileEl = document.getElementById("pemfile");
    var pw = document.getElementById("importpw").value || "";
    if (!fileEl.files || !fileEl.files[0]) { toast("Choose your backup file first"); return; }
    if (!pw) { toast("Enter the passphrase for that backup"); return; }
    var reader = new FileReader();
    reader.onload = function () {
      api("POST", "/api/key/import", { pem: reader.result, passphrase: pw }).then(function (res) {
        if (!res.ok || !res.data.ok) { toast(res.data.error || "Could not import that key"); return; }
        finish();
      }).catch(function () { toast("The local server did not respond"); });
    };
    reader.onerror = function () { toast("Could not read that file"); };
    reader.readAsText(fileEl.files[0]);
  };

  window.downloadBackup = function () {
    fetch("/api/key/export").then(function (r) {
      if (!r.ok) throw new Error("no key");
      return r.blob();
    }).then(function (blob) {
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = url; a.download = "owner.pem";
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      toast("Download started. Keep owner.pem somewhere safe, off this machine.");
    }).catch(function () { toast("No key to back up yet"); });
  };

  function wipeSecrets() {
    lastGenerated = null;
    ["pw", "importpw"].forEach(function (id) { var el = document.getElementById(id); if (el) el.value = ""; });
    var box = document.getElementById("genpw-box");
    if (box) { box.textContent = ""; box.classList.add("hidden"); }
  }

  window.finish = function () {
    api("GET", "/api/status").then(function (res) { routeIn(res.data || {}); wipeSecrets(); })
      .catch(function () { toast("The local server did not respond"); });
  };

  var fullDid = null;

  function enterApp(status, forceTab) {
    clearDepTimers();
    fullDid = (status && status.did) || null;
    var s = shortDid(fullDid);
    document.getElementById("you-did").textContent = s;
    document.getElementById("composer-did").textContent = s;
    document.getElementById("id-did").textContent = fullDid || "…";
    document.getElementById("setup").classList.add("hidden");
    document.getElementById("app").classList.remove("hidden");
    var ch = document.getElementById("conn-host"); if (ch) ch.textContent = location.host;
    reflectTheme();
    refreshChatLock();
    if (forceTab) {                                  // a caller that knows where to land (B -> My Agent)
      api("GET", "/api/agent").then(function (r) { reflectAgentPill(r.data || {}); }).catch(function () {});
      tab(forceTab); window.scrollTo(0, 0); return;
    }
    api("GET", "/api/agent").then(function (r) {
      var a = r.data || {};
      reflectAgentPill(a);
      if (!a.linked) { tab("rooms"); return; }
      api("GET", "/api/grant").then(function (gr) {
        var g = gr.data || {};
        tab((!g.active && !g.revoked) ? "agent" : "rooms");
      }).catch(function () { tab("rooms"); });
    }).catch(function () { tab("rooms"); });
    window.scrollTo(0, 0);
  }

  window.scrollToGrant = function () {
    tab("agent");
    var el = document.getElementById("signgrantbtn");
    if (el && el.scrollIntoView) el.scrollIntoView({ behavior: "smooth", block: "center" });
    var pw = document.getElementById("grantpw"); if (pw) pw.focus();
  };

  window.copyDid = function () {
    if (!fullDid) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(fullDid).then(function () { toast("Copied your did to the clipboard"); },
        function () { toast("Could not copy; select it to copy by hand"); });
    } else {
      toast("Select the did to copy it");
    }
  };

  window.tab = function (name) {
    document.querySelectorAll(".tab").forEach(function (t) { t.classList.toggle("on", t.dataset.tab === name); });
    document.querySelectorAll("[data-panel]").forEach(function (p) { p.classList.toggle("hidden", p.dataset.panel !== name); });
    var cpw = document.getElementById("chatpw"); if (cpw) cpw.value = "";
    var upw = document.getElementById("unlockpw"); if (upw) upw.value = "";
    var jpw = document.getElementById("jobpw"); if (jpw) jpw.value = "";
    var gpw = document.getElementById("grantpw"); if (gpw) gpw.value = "";
    var apw = document.getElementById("approvepw"); if (apw) apw.value = "";
    var tpw = document.getElementById("taskpw"); if (tpw) tpw.value = "";
    var kpw = document.getElementById("costpw"); if (kpw) kpw.value = "";
    if (name === "rooms") {
      loadRooms();
      updateLockUI();
    } else if (name === "board") {
      loadBoard(); loadMine();
    } else if (name === "agent") {
      loadAgent();
    } else if (name === "tasks") {
      loadTasks();
    } else if (name === "settings") {
      refreshChatLock();
      loadCost();
    }
    window.scrollTo(0, 0);
  };

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  var roomlist = document.getElementById("roomlist");
  var chat = document.getElementById("chat");
  var currentRoom = null, lastSeq = null, highestSeq = -1, pollTimer = null;
  var roomGen = 0;
  var posting = false;

  function displayText(s) {
    if (typeof s !== "string") return "";
    var out = "";
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      var bad = (c < 0x20) || (c >= 0x7f && c <= 0x9f) || c === 0x200e || c === 0x200f ||
                (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069);
      out += bad ? " " : s.charAt(i);
    }
    return out;
  }

  function clearPlaceholder() {
    var ph = chat.querySelector(".placeholder, .hint");
    if (ph) ph.remove();
  }

  function addMsg(cls, avClass, avLetter, nm, badge, bcolor, tx) {
    var d = el("div", "msg" + (cls ? " " + cls : ""));
    var avn = el("div", "av " + avClass, avLetter);
    var bub = el("div", "bub");
    var nmn = el("div", "nm");
    nmn.appendChild(document.createTextNode(nm + " "));
    if (badge) {
      var v = el("span", "verified", "✓ " + badge);
      if (bcolor) v.style.color = bcolor;
      nmn.appendChild(v);
    } else {
      nmn.appendChild(el("span", "anon", "unverified"));
    }
    bub.appendChild(nmn);
    bub.appendChild(el("div", "tx", displayText(tx)));
    d.appendChild(avn); d.appendChild(bub);
    chat.appendChild(d); chat.scrollTop = chat.scrollHeight;
  }

  function renderMsg(m) {
    if (m.seq != null) {
      if (m.seq <= highestSeq) return;
      highestSeq = m.seq;
    }
    clearPlaceholder();
    var verified = !!m.verified;
    var mine = verified && fullDid && m.from === fullDid;
    if (mine) {
      addMsg("mine", "you", "Y", "you", "signed", "var(--human)", m.text);
    } else if (verified) {
      var sd = shortDid(m.from);
      addMsg("", "o", (sd[0] || "?").toUpperCase(), sd, "signed", "var(--proto)", m.text);
    } else {
      addMsg("", "o", "~", m.from || "~anon", null, null, m.text);
    }
  }

  function loadRooms() {
    api("GET", "/api/rooms").then(function (res) {
      roomlist.textContent = "";
      var rooms = (res.data && res.data.rooms) || [];
      if (!res.ok || !rooms.length) {
        roomlist.appendChild(el("div", "hint", res.ok ? "No rooms are listed right now." :
          (res.data.error || "Could not reach the protocol.")));
        return;
      }
      rooms.forEach(function (r) {
        var b = el("button", "rm" + (r.room === currentRoom ? " on" : ""));
        var isMb = r.kind === "mailbox" || r.kind === "mailbox_private";
        b.appendChild(el("span", "kind" + (isMb ? " mb" : ""), isMb ? "mailbox" : "room"));
        b.appendChild(el("span", "nm", r.room));
        b.title = r.topic || "";
        b.onclick = function () { openRoom(r.room); };
        roomlist.appendChild(b);
      });
      if (res.data.truncated || rooms.length >= 60) {
        roomlist.appendChild(el("div", "hint", "Showing the " + rooms.length + " most active rooms."));
      }
    }).catch(function () {
      roomlist.textContent = ""; roomlist.appendChild(el("div", "hint", "The local server did not respond."));
    });
  }

  function markActive() {
    roomlist.querySelectorAll(".rm").forEach(function (b) {
      var nm = b.querySelector(".nm");
      b.classList.toggle("on", !!nm && nm.textContent === currentRoom);
    });
  }

  function openRoom(room) {
    currentRoom = room; lastSeq = null; highestSeq = -1;
    var gen = ++roomGen;
    document.getElementById("composer-room").textContent = room;
    document.getElementById("chatpw").value = "";
    updateLockUI();
    markActive();
    chat.textContent = "";
    chat.appendChild(el("div", "hint", "Loading " + room + "…"));
    api("GET", "/api/room?room=" + encodeURIComponent(room)).then(function (res) {
      if (gen !== roomGen) return;
      chat.textContent = "";
      if (!res.ok) {
        chat.appendChild(el("div", "hint", (res.data && res.data.error) || "Could not read that room."));
        return;
      }
      var msgs = res.data.messages || [];
      if (!msgs.length) { chat.appendChild(el("div", "placeholder", "No messages yet. Be the first.")); }
      msgs.forEach(renderMsg);
      lastSeq = (typeof res.data.last_seq === "number") ? res.data.last_seq : 0;
      startPoll();
    }).catch(function () {
      if (gen === roomGen) { chat.textContent = ""; chat.appendChild(el("div", "hint", "The local server did not respond.")); }
    });
  }

  function startPoll() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(pollOnce, 4000);
  }
  function roomsVisible() {
    var p = document.querySelector('[data-panel="rooms"]');
    return p && !p.classList.contains("hidden");
  }
  function pollOnce() {
    if (!currentRoom || lastSeq == null || !roomsVisible()) return;
    var room = currentRoom, gen = roomGen, since = lastSeq;
    api("GET", "/api/room?room=" + encodeURIComponent(room) + "&since=" + encodeURIComponent(since))
      .then(function (res) {
        if (gen !== roomGen || !res.ok) return;
        (res.data.messages || []).forEach(renderMsg);
        if (typeof res.data.last_seq === "number" && res.data.last_seq > lastSeq) {
          lastSeq = res.data.last_seq;
        }
      }).catch(function () {});
  }

  window.toggleChatPw = function () {
    var el2 = document.getElementById("chatpw"), btn = document.getElementById("chatpwshow");
    var showing = el2.type === "text";
    el2.type = showing ? "password" : "text";
    btn.textContent = showing ? "Show" : "Hide";
  };

  window.postMsg = function () {
    if (posting) return;
    if (!currentRoom) { toast("Pick a room on the left first"); return; }
    var box = document.getElementById("chatbox"), pwEl = document.getElementById("chatpw");
    var btn = document.getElementById("postbtn");
    var t = (box.value || "").trim();
    if (!t) return;
    var body = { room: currentRoom, text: t };
    var usedPw = false;
    if (chatUnlockRemaining() <= 0) {
      var pw = pwEl.value || "";
      if (!pw) {
        document.getElementById("chatpw-row").classList.remove("hidden");
        toast("Unlock chat in Settings, or enter your passphrase to post once");
        return;
      }
      body.passphrase = pw; usedPw = true;
    }
    posting = true; if (btn) btn.disabled = true;
    api("POST", "/api/room/say", body).then(function (res) {
      if (res.status === 403) {
        if (usedPw) pwEl.value = "";
        toast((res.data && res.data.error) || "That passphrase did not unlock your key");
        if (res.data && res.data.need === "unlock") {
          refreshChatLock();
          document.getElementById("chatpw-row").classList.remove("hidden");
        }
        return;
      }
      if (!res.ok || !res.data.ok) { toast((res.data && res.data.error) || "The post did not go through"); return; }
      box.value = ""; if (usedPw) pwEl.value = "";
      pollOnce();
      toast("Posted to " + currentRoom);
    }).catch(function () { toast("The local server did not respond"); })
      .then(function () { posting = false; if (btn) btn.disabled = false; });
  };

  var chatUntil = 0;
  var lockTicker = null;

  function chatUnlockRemaining() { return Math.max(0, Math.floor(chatUntil - Date.now() / 1000)); }
  function fmtLeft(s) {
    var m = Math.floor(s / 60), ss = s % 60;
    return m + ":" + (ss < 10 ? "0" : "") + ss;
  }

  window.toggleUnlockPw = function () {
    var el2 = document.getElementById("unlockpw"), btn = document.getElementById("unlockpwshow");
    var showing = el2.type === "text";
    el2.type = showing ? "password" : "text";
    btn.textContent = showing ? "Show" : "Hide";
  };

  var selectedSecs = 900;
  function selectDur(secs, btn) {
    selectedSecs = secs;
    var dc = document.getElementById("durcustom"); if (dc) dc.value = "";
    document.querySelectorAll("#durpicks button").forEach(function (b) { b.classList.toggle("on", b === btn); });
  }

  window.unlockChat = function () {
    var pw = (document.getElementById("unlockpw").value || "");
    if (!pw) { toast("Enter your passphrase to unlock"); return; }
    var custom = parseInt(document.getElementById("durcustom").value, 10);
    var secs = (custom > 0) ? custom * 60 : selectedSecs;
    api("POST", "/api/chat/unlock", { passphrase: pw, seconds: secs }).then(function (res) {
      if (res.status === 403) { toast("That passphrase did not unlock your key"); return; }
      if (!res.ok || !res.data.ok) { toast((res.data && res.data.error) || "Could not unlock chat"); return; }
      chatUntil = res.data.until;
      updateLockUI(); startLockTicker();
      toast("Chat unlocked for " + fmtLeft(chatUnlockRemaining()));
    }).catch(function () { toast("The local server did not respond"); })
      .then(function () { var u = document.getElementById("unlockpw"); if (u) u.value = ""; });
  };

  window.lockChat = function () {
    api("POST", "/api/chat/lock", {}).then(function () {
      chatUntil = 0; updateLockUI();
      toast("Chat locked");
    }).catch(function () { toast("The local server did not respond"); });
  };

  function refreshChatLock() {
    api("GET", "/api/chat/status").then(function (res) {
      chatUntil = (res.data && res.data.unlocked) ? res.data.until : 0;
      updateLockUI();
      if (chatUntil > 0) startLockTicker();
    }).catch(function () {});
  }

  function startLockTicker() {
    if (lockTicker) clearInterval(lockTicker);
    lockTicker = setInterval(function () {
      updateLockUI();
      if (chatUnlockRemaining() <= 0) { clearInterval(lockTicker); lockTicker = null; }
    }, 1000);
  }

  function updateLockUI() {
    var rem = chatUnlockRemaining();
    var unlocked = rem > 0;

    var st = document.getElementById("set-lockstate");
    var controls = document.getElementById("set-unlock-controls");
    if (st) {
      st.textContent = "";
      st.className = "banner " + (unlocked ? "good" : "");
      if (unlocked) {
        st.appendChild(document.createTextNode("Chat is unlocked · " + fmtLeft(rem) + " left  "));
        var lb = el("button", "btn ghost sm", "Lock now"); lb.onclick = lockChat;
        st.appendChild(lb);
      } else {
        st.appendChild(document.createTextNode("Chat is locked. Each post asks for your passphrase."));
      }
    }
    if (controls) controls.classList.toggle("hidden", unlocked);

    var line = document.getElementById("chatlock");
    if (line) {
      line.textContent = "";
      line.appendChild(el("span", "dot " + (unlocked ? "on" : "off")));
      if (unlocked) {
        line.appendChild(document.createTextNode("Chat unlocked · " + fmtLeft(rem) + " left  "));
        var lk = el("button", "link", "Lock now"); lk.onclick = lockChat;
        line.appendChild(lk);
        document.getElementById("chatpw-row").classList.add("hidden");
      } else {
        line.appendChild(document.createTextNode("Locked. Type your passphrase to post once, or "));
        var un = el("button", "link", "unlock chat in Settings"); un.onclick = function () { tab("settings"); };
        line.appendChild(un);
        document.getElementById("chatpw-row").classList.remove("hidden");
      }
    }
  }

  var joblist = document.getElementById("joblist");
  var myjobsEl = document.getElementById("myjobs");
  var boardStat = document.getElementById("boardstat");
  var KNOWN_STATUS = ["open", "claimed", "delivered", "attested", "rejected"];
  var jobPosting = false;

  function renderJob(j) {
    var row = el("div", "job");
    var status = (KNOWN_STATUS.indexOf(j.status) >= 0) ? j.status : "open";
    row.appendChild(el("span", "st " + status, status));
    var mid = el("div"); mid.style.flex = "1";
    var titleRow = el("div", "jobtitle");
    if (j.category) titleRow.appendChild(el("span", "cat " + j.category, j.category));
    titleRow.appendChild(el("span", "t", displayText(j.title) || "(untitled)"));
    mid.appendChild(titleRow);
    if (j.body) mid.appendChild(el("div", "d", displayText(j.body)));
    row.appendChild(mid);
    var votes = el("span", "votes");
    votes.appendChild(el("span", "up", "↑ " + j.useful_n));
    votes.appendChild(el("span", "down", "↓ " + j.not_n));
    row.appendChild(votes);
    return row;
  }

  window.loadBoard = function () {
    boardStat.textContent = "Loading the board…";
    api("GET", "/api/board").then(function (res) {
      if (!res.ok) { boardStat.textContent = (res.data && res.data.error) || "Could not reach the board"; return; }
      var d = res.data || {}, jobs = d.jobs || [], stats = d.stats || {};
      joblist.textContent = "";
      if (!jobs.length) { joblist.appendChild(el("div", "hint", "No open jobs in the board window right now.")); }
      jobs.forEach(function (j) { joblist.appendChild(renderJob(j)); });
      var bits = [];
      if (typeof stats.open === "number") bits.push(stats.open.toLocaleString() + " open");
      if (typeof stats.agents === "number") bits.push(stats.agents.toLocaleString() + " agents");
      bits.push("showing " + jobs.length);
      boardStat.textContent = bits.join(" · ");
    }).catch(function () { boardStat.textContent = "The local server did not respond"; });
  };

  window.loadMine = function () {
    api("GET", "/api/board/mine").then(function (res) {
      var mine = (res.data && res.data.jobs) || [];
      myjobsEl.textContent = "";
      if (!mine.length) { myjobsEl.appendChild(el("div", "hint", "Nothing yet. Post a job and it shows here.")); return; }
      mine.forEach(function (j) {
        var row = el("div", "job");
        row.appendChild(el("span", "st open", "posted"));
        var mid = el("div"); mid.style.flex = "1";
        var tr = el("div", "jobtitle");
        if (j.category) tr.appendChild(el("span", "cat " + j.category, j.category));
        tr.appendChild(el("span", "t", displayText(j.title)));
        mid.appendChild(tr);
        mid.appendChild(el("div", "d mono", j.job_id));
        row.appendChild(mid);
        myjobsEl.appendChild(row);
      });
    }).catch(function () {});
  };

  window.toggleJobPw = function () {
    var e = document.getElementById("jobpw"), btn = document.getElementById("jobpwshow");
    var showing = e.type === "text";
    e.type = showing ? "password" : "text";
    btn.textContent = showing ? "Show" : "Hide";
  };

  window.postJob = function () {
    if (jobPosting) return;
    var catEl = document.getElementById("jcat"), tEl = document.getElementById("jt"),
        sEl = document.getElementById("js"), pwEl = document.getElementById("jobpw"),
        btn = document.getElementById("jobpostbtn");
    var category = catEl.value, t = (tEl.value || "").trim(), s = (sEl.value || "").trim(), pw = pwEl.value || "";
    if (!t) { toast("Give the job a title"); return; }
    if (!s) { toast("Say what a good delivery looks like"); return; }
    if (!pw) { toast("Enter your passphrase to sign the post"); return; }
    jobPosting = true; if (btn) btn.disabled = true;
    api("POST", "/api/board/post", { category: category, title: t, body: s, passphrase: pw }).then(function (res) {
      if (res.status === 403) { pwEl.value = ""; toast((res.data && res.data.error) || "That passphrase did not unlock your key"); return; }
      if (!res.ok || !res.data.ok) { toast((res.data && res.data.error) || "The job did not post"); return; }
      tEl.value = ""; sEl.value = "";
      loadMine();
      toast("Posted to the board");
    }).catch(function () { toast("The local server did not respond"); })
      .then(function () {
        pwEl.value = "";
        jobPosting = false; if (btn) btn.disabled = false;
      });
  };

  var KNOB_DEFAULT_CEILING = 50;

  function showAgentState(linked) {
    document.getElementById("agent-unlinked").classList.toggle("hidden", linked);
    document.getElementById("agent-linked").classList.toggle("hidden", !linked);
  }

  function reflectAgentPill(a) {
    var linked = a && a.linked;
    var nick = linked ? (displayText(a.nick) || "Agent") : "Agent";
    var pill = document.getElementById("agent-pill");
    if (pill) {
      var who = pill.querySelector(".who"), did = pill.querySelector(".did");
      pill.className = linked ? "idpill agent" : "idpill muted";
      if (who) who.textContent = nick;
      if (did) did.textContent = linked ? shortDid(a.agent_did) : "not linked yet";
    }
    var keyLine = document.getElementById("agent-key-line");
    if (keyLine) keyLine.textContent = linked ? (nick + " · " + shortDid(a.agent_did)) : "No agent linked yet";
  }

  window.loadAgent = function () {
    api("GET", "/api/agent").then(function (res) {
      var a = res.data || {}, sel = document.getElementById("agentsel");
      reflectAgentPill(a);
      if (!a.linked) { sel.textContent = "No agent linked yet"; showAgentState(false); return; }
      sel.textContent = (a.nick ? displayText(a.nick) + " · " : "") + shortDid(a.agent_did);
      showAgentState(true);
      loadGrant(); loadFeed(); loadPending(); loadAgentHealth();
    }).catch(function () { toast("The local server did not respond"); });
  };

  function loadAgentHealth() {
    api("GET", "/api/cost").then(function (r) {
      renderHealth((r.data || {}).health, "agent-health");
    }).catch(function () {});
  }

  window.linkAgent = function () {
    var did = (document.getElementById("agentdid").value || "").trim();
    var nick = (document.getElementById("agentnick").value || "").trim();
    if (!did) { toast("Paste your agent's did:key"); return; }
    var btn = document.getElementById("linkbtn"); if (btn) btn.disabled = true;
    api("POST", "/api/agent/link", { agent_did: did, nick: nick }).then(function (res) {
      if (!res.ok || !res.data.ok) { toast((res.data && res.data.error) || "Could not link that agent"); return; }
      document.getElementById("agentdid").value = "";
      loadAgent(); toast("Agent linked");
    }).catch(function () { toast("The local server did not respond"); })
      .then(function () { if (btn) btn.disabled = false; });
  };

  window.unlinkAgent = function () {
    api("POST", "/api/agent/unlink", {}).then(function (res) {
      if (!res.ok || !res.data.ok) { toast((res.data && res.data.error) || "Could not unlink the agent"); return; }
      loadAgent(); toast("Agent unlinked");
    }).catch(function () { toast("The local server did not respond"); });
  };

  window.toggleGrantPw = function () {
    var e = document.getElementById("grantpw");
    var showing = e.type === "text";
    e.type = showing ? "password" : "text";
    var btn = e.parentNode.querySelector("button");
    if (btn) btn.textContent = showing ? "Show" : "Hide";
  };

  function ceilingFor(allowList, klass) {
    for (var i = 0; i < allowList.length; i++) if (allowList[i].klass === klass) return allowList[i].ceiling;
    return null;
  }

  function renderKnobs(knobs, allowList) {
    var wrap = document.getElementById("knobs");
    wrap.textContent = "";
    knobs.forEach(function (k) {
      var cur = ceilingFor(allowList, k.klass), on = cur != null;
      var row = el("div", "row" + (k.dangerous ? " flagged" : ""));
      row.dataset.klass = k.klass;
      var left = el("div"); left.style.flex = "1";
      var name = el("div", "name");
      name.appendChild(document.createTextNode(k.label));
      name.appendChild(el("span", "tag " + (k.dangerous ? "danger" : "safe"), k.dangerous ? "⚠ risky" : "low risk"));
      left.appendChild(name);
      left.appendChild(el("div", "desc", k.about));
      var right = el("div", "right");
      var capIn = el("input", "capin mono"); capIn.type = "number"; capIn.min = "1";
      capIn.value = on ? cur : KNOB_DEFAULT_CEILING; capIn.title = "actions per day";
      capIn.style.display = on ? "" : "none";
      var perday = el("span", "perday", "/day"); perday.style.display = on ? "" : "none";
      var tg = el("button", "toggle" + (on ? " on" : "") + (k.dangerous ? " dgr" : "")); tg.type = "button";
      tg.appendChild(el("i"));
      tg.onclick = function () {
        var nowOn = !tg.classList.contains("on");
        tg.classList.toggle("on", nowOn);
        capIn.style.display = nowOn ? "" : "none"; perday.style.display = nowOn ? "" : "none";
      };
      right.appendChild(capIn); right.appendChild(perday); right.appendChild(tg);
      row.appendChild(left); row.appendChild(right);
      row._toggle = tg; row._cap = capIn;
      wrap.appendChild(row);
    });
  }

  function loadGrant() {
    api("GET", "/api/grant").then(function (res) {
      var g = res.data || {};
      renderKnobs(g.knobs || [], g.allow || []);
      var state = document.getElementById("agentstate"),
          stext = document.getElementById("agentstatetext"),
          line = document.getElementById("grantline"),
          wake = document.getElementById("wake-banner");
      if (wake) wake.classList.toggle("hidden", !(!g.active && !g.revoked));
      var unsent = document.getElementById("grant-unsent");
      if (unsent) unsent.classList.toggle("hidden", !g.unsent);
      if (g.active) {
        state.className = "live on"; stext.textContent = "Running on auto";
        var days = Math.max(0, Math.round((g.expires_in || 0) / 86400));
        var n = (g.allow || []).length;
        line.textContent = n + " permission" + (n === 1 ? "" : "s") + " on auto · expires in " + days + " day" + (days === 1 ? "" : "s");
      } else {
        state.className = "live off";
        stext.textContent = g.revoked ? "Revoked, everything asks you" : "No grant, everything asks you";
        line.textContent = g.revoked ? "Revoked. Sign a new grant to run on auto again." : "Sign a grant to let it act on its own.";
      }
    }).catch(function () {});
  }

  window.signGrant = function () {
    var allow = {}, bad = false;
    document.querySelectorAll("#knobs .row").forEach(function (row) {
      if (row._toggle.classList.contains("on")) {
        var c = parseInt(row._cap.value, 10);
        if (!(c > 0)) bad = true;
        allow[row.dataset.klass] = c;
      }
    });
    if (bad) { toast("Give each permission you turn on a daily limit of at least 1"); return; }
    var pw = document.getElementById("grantpw").value || "";
    if (!pw) { toast("Enter your passphrase to sign the grant"); return; }
    var dur = parseInt(document.getElementById("grantdur").value, 10);
    var btn = document.getElementById("signgrantbtn"); if (btn) btn.disabled = true;
    api("POST", "/api/grant/sign", { allow: allow, duration_seconds: dur, passphrase: pw }).then(function (res) {
      if (res.status === 403) { toast((res.data && res.data.error) || "That passphrase did not unlock your key"); return; }
      if (!res.ok || !res.data.ok) { toast((res.data && res.data.error) || "Could not sign the grant"); return; }
      loadGrant();
      if (res.data.published === false) {
        toast("Grant signed, but it could not reach your agent. It keeps its previous permission until you retry.");
      } else {
        toast("Grant signed and sent to your agent.");
      }
    }).catch(function () { toast("The local server did not respond"); })
      .then(function () { document.getElementById("grantpw").value = ""; if (btn) btn.disabled = false; });
  };

  window.resendGrant = function () {
    var btn = document.querySelector("#grant-unsent button"); if (btn) btn.disabled = true;
    api("POST", "/api/grant/resend", {}).then(function (res) {
      if (!res.ok || !res.data.ok) { toast((res.data && res.data.detail) || "Could not resend the grant"); return; }
      loadGrant();
      toast(res.data.published === false
        ? "Still could not reach your agent. Check your connection and try once more."
        : "Grant sent to your agent.");
    }).catch(function () { toast("The local server did not respond"); })
      .then(function () { if (btn) btn.disabled = false; });
  };

  window.openStopModal = function () {
    var m = document.getElementById("stopmodal");
    var pw = document.getElementById("stoppw"); if (pw) pw.value = "";
    m.classList.remove("hidden");
    if (pw) pw.focus();
  };
  window.closeStopModal = function () {
    document.getElementById("stopmodal").classList.add("hidden");
    var pw = document.getElementById("stoppw"); if (pw) pw.value = "";
  };
  window.toggleStopPw = function () {
    var e = document.getElementById("stoppw");
    var showing = e.type === "text";
    e.type = showing ? "password" : "text";
    var btn = e.parentNode.querySelector("button");
    if (btn) btn.textContent = showing ? "Show" : "Hide";
  };
  window.confirmStop = function () {
    var pw = document.getElementById("stoppw").value || "";
    if (!pw) { toast("Enter your passphrase to sign the stop (a real stop must be signed by your key)"); return; }
    var btn = document.getElementById("confirmstopbtn"); if (btn) btn.disabled = true;
    api("POST", "/api/grant/revoke", { passphrase: pw }).then(function (res) {
      if (res.status === 403) { toast((res.data && res.data.error) || "That passphrase did not unlock your key"); return; }
      if (!res.ok || !res.data.ok) { toast((res.data && res.data.error) || "Could not stop the agent"); return; }
      closeStopModal();
      loadGrant();
      if (res.data.published === false) {
        toast("Stop signed, but it could not reach your agent. Check your connection and press Stop again.");
      } else {
        toast("Agent stopped. It halts within a minute and stays stopped until you sign a new grant.");
      }
    }).catch(function () { toast("The local server did not respond"); })
      .then(function () { if (btn) btn.disabled = false; });
  };

  function loadFeed() {
    api("GET", "/api/agent/feed").then(function (res) {
      var d = res.data || {}, items = d.items || [], wrap = document.getElementById("feed");
      wrap.textContent = "";
      document.getElementById("feednote").textContent = d.note || "A record you read, not a queue you clear.";
      if (!items.length) { wrap.appendChild(el("div", "hint", "Nothing from your agent on the board yet.")); return; }
      items.forEach(function (it) {
        var ev = el("div", "ev");
        ev.appendChild(el("span", "mk " + (it.role === "posted" ? "m-agent" : "m-good")));
        var body = el("div"); body.style.flex = "1";
        body.appendChild(el("div", "line", (it.role === "posted" ? "Posted" : "Working") + ": " + displayText(it.title)));
        body.appendChild(el("div", "meta", (it.category || "") + " · " + (it.status || "") + " · ↑" + it.useful_n + " ↓" + it.not_n));
        ev.appendChild(body);
        wrap.appendChild(ev);
      });
    }).catch(function () {});
  }

  var taskState = [];
  var taskSigned = [];
  var taskPublished = null;
  var taskPlaybook = [];
  var taskMax = 8;
  var taskSchedules = ["once", "hourly", "daily", "weekly"];
  var TASK_DRAFT_KEY = "flop.taskdraft";

  function persistDraft() {
    try { localStorage.setItem(TASK_DRAFT_KEY, JSON.stringify(taskState)); } catch (e) {}
  }
  function loadDraft() {
    try { var v = JSON.parse(localStorage.getItem(TASK_DRAFT_KEY)); return Array.isArray(v) ? v : null; }
    catch (e) { return null; }
  }
  function clearDraft() { try { localStorage.removeItem(TASK_DRAFT_KEY); } catch (e) {} }
  function tasksEqual(a, b) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i].id !== b[i].id || a[i].text !== b[i].text || a[i].schedule !== b[i].schedule) return false;
    }
    return true;
  }
  function updateTaskStatus() {
    var pub = document.getElementById("tasks-published");
    var btn = document.getElementById("savetasksbtn");
    var dirty = !tasksEqual(taskState, taskSigned);
    if (btn) btn.classList.toggle("nudge", dirty);
    if (!pub) return;
    if (dirty) {
      var n = taskState.length;
      pub.className = "sub warn-text";
      pub.textContent = "Unsigned changes. Sign and send to make " + (n === 1 ? "it" : "them") + " live.";
    } else if (taskPublished === true) {
      pub.className = "sub"; pub.textContent = "Sent to your agent.";
    } else if (taskPublished === false) {
      pub.className = "sub"; pub.textContent = "Saved locally; the last send did not reach your agent. Sign and send again.";
    } else {
      pub.className = "sub"; pub.textContent = "";
    }
  }
  function taskChanged() { persistDraft(); renderTaskList(); renderPlaybook(); updateTaskStatus(); }

  window.toggleTaskPw = function () {
    var el2 = document.getElementById("taskpw");
    el2.type = el2.type === "text" ? "password" : "text";
  };
  window.copyTaskSecret = function () {
    var el2 = document.getElementById("task-secret");
    if (!el2 || !el2.value) return;
    if (navigator.clipboard) { navigator.clipboard.writeText(el2.value).then(function () { toast("Secret copied. Set it as TASK_SECRET on your agent."); }, function () {}); }
    else { el2.select(); toast("Select and copy the secret."); }
  };

  function slugId(text) {
    var base = (text || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40);
    if (!base) base = "task";
    var id = base, n = 2, used = {};
    taskState.forEach(function (t) { used[t.id] = true; });
    while (used[id]) { id = (base + "-" + n).slice(0, 48); n++; }
    return id;
  }

  function loadTasks() {
    api("GET", "/api/tasks").then(function (res) {
      var d = res.data || {};
      var linked = !!d.agent_linked && !!d.has_key;
      document.getElementById("tasks-gate").classList.toggle("hidden", linked);
      document.getElementById("tasks-main").classList.toggle("hidden", !linked);
      if (!linked) return;
      taskPlaybook = d.playbook || [];
      taskMax = d.max_tasks || 8;
      taskSchedules = d.schedules || taskSchedules;
      taskSigned = (d.tasks || []).map(function (t) { return { id: t.id, text: t.text, schedule: t.schedule }; });
      taskPublished = (d.published === true || d.published === false) ? d.published : null;
      var draft = loadDraft();
      taskState = draft ? draft : taskSigned.map(function (t) { return { id: t.id, text: t.text, schedule: t.schedule }; });
      document.getElementById("task-max").textContent = String(taskMax);
      var dep = d.deploy || {};
      var secEl = document.getElementById("task-secret"); if (secEl) secEl.value = dep.task_secret || "";
      renderModelChoices(dep.model_choices || [], dep.model);
      renderPlaybook();
      renderTaskList();
      updateTaskStatus();
    }).catch(function () { toast("The local server did not respond"); });
  }

  function renderModelChoices(choices, current) {
    var sel = document.getElementById("task-model");
    if (!sel) return;
    sel.textContent = "";
    choices.forEach(function (c) {
      var o = el("option", null, c.label + (c.free ? " · free" : ""));
      o.value = c.id; if (c.id === current) o.selected = true;
      sel.appendChild(o);
    });
  }

  function renderPlaybook() {
    var wrap = document.getElementById("playbook");
    wrap.textContent = "";
    var have = {};
    taskState.forEach(function (t) { have[t.id] = true; });
    taskPlaybook.forEach(function (p) {
      var row = el("div", "pbrow");
      var left = el("div"); left.style.flex = "1";
      left.appendChild(el("div", "name", displayText(p.text)));
      left.appendChild(el("div", "desc", displayText(p.why || "") + "  ·  suggested: " + p.schedule));
      var btn = el("button", "btn ghost sm", have[p.id] ? "Added" : "Add");
      btn.type = "button"; btn.disabled = !!have[p.id];
      btn.onclick = function () { addPlaybookTask(p.id); };
      row.appendChild(left); row.appendChild(btn);
      wrap.appendChild(row);
    });
  }

  function renderTaskList() {
    var wrap = document.getElementById("tasklist");
    wrap.textContent = "";
    if (!taskState.length) { wrap.appendChild(el("div", "hint", "No tasks yet. Add from the starter playbook, or write your own below.")); return; }
    taskState.forEach(function (t, i) {
      var row = el("div", "taskrow");
      var body = el("div"); body.style.flex = "1";
      body.appendChild(el("div", "name", displayText(t.text)));
      body.appendChild(el("div", "meta", t.id));
      var sel = el("select", "input sm");
      taskSchedules.forEach(function (s) {
        var o = el("option", null, s); o.value = s; if (s === t.schedule) o.selected = true; sel.appendChild(o);
      });
      sel.onchange = function () { taskState[i].schedule = sel.value; persistDraft(); updateTaskStatus(); };
      var rm = el("button", "btn ghost sm", "Remove"); rm.type = "button";
      rm.onclick = function () { taskState.splice(i, 1); taskChanged(); };
      var right = el("div", "right"); right.appendChild(sel); right.appendChild(rm);
      row.appendChild(body); row.appendChild(right);
      wrap.appendChild(row);
    });
  }

  function addPlaybookTask(id) {
    if (taskState.length >= taskMax) { toast("That is the most tasks a playbook can hold (" + taskMax + ")."); return; }
    var p = taskPlaybook.filter(function (x) { return x.id === id; })[0];
    if (!p) return;
    if (taskState.some(function (t) { return t.id === id; })) return;
    taskState.push({ id: p.id, text: p.text, schedule: p.schedule });
    taskChanged();
  }

  window.addCustomTask = function () {
    var textEl = document.getElementById("task-new-text"), schedEl = document.getElementById("task-new-sched");
    var text = (textEl.value || "").trim();
    if (!text) { toast("Write what you want your agent to do"); return; }
    if (taskState.length >= taskMax) { toast("That is the most tasks a playbook can hold (" + taskMax + ")."); return; }
    taskState.push({ id: slugId(text), text: text.slice(0, 240), schedule: schedEl.value || "daily" });
    textEl.value = "";
    taskChanged();
  };

  window.saveTasks = function () {
    if (!taskState.length) { toast("Add at least one task before sending"); return; }
    var pw = document.getElementById("taskpw").value || "";
    if (!pw) { toast("Enter your passphrase to sign the playbook"); return; }
    var btn = document.getElementById("savetasksbtn"); if (btn) btn.disabled = true;
    api("POST", "/api/tasks/save", { tasks: taskState, passphrase: pw }).then(function (res) {
      if (res.status === 403) { toast((res.data && res.data.error) || "That passphrase did not unlock your key"); return; }
      if (!res.ok || !res.data.ok) { toast((res.data && res.data.error) || "Could not send the tasks"); return; }
      if (res.data.published === false) {
        toast("Playbook saved, but it could not reach your agent. It keeps its previous tasks until you retry.");
      } else {
        toast("Playbook signed and sent to your agent.");
      }
      clearDraft();
      loadTasks();
    }).catch(function () { toast("The local server did not respond"); })
      .then(function () { document.getElementById("taskpw").value = ""; if (btn) btn.disabled = false; });
  };

  window.saveModel = function () {
    var sel = document.getElementById("task-model");
    var model = sel && sel.value;
    if (!model) { toast("Choose a model"); return; }
    api("POST", "/api/config/save", { model: model }).then(function (res) {
      if (!res.ok || !res.data.ok) { toast((res.data && res.data.error) || "Could not save the model choice"); return; }
      toast("Model choice saved. Set it on your agent at deploy.");
    }).catch(function () { toast("The local server did not respond"); });
  };

  function loadPending() {
    api("GET", "/api/pending").then(function (res) {
      var d = res.data || {}, cards = d.pending || [], wrap = document.getElementById("approvewrap");
      wrap.textContent = "";
      if (!cards.length) return;
      var card = cards[0];
      var box = el("div", "approve");
      var head = el("div"); head.style.display = "flex"; head.style.alignItems = "center"; head.style.gap = "8px";
      head.appendChild(el("span", "tag danger", "⚠ needs you"));
      var sub = el("span", "sub"); sub.style.marginLeft = "auto"; sub.textContent = "a gated action, waiting";
      head.appendChild(sub); box.appendChild(head);
      box.appendChild(el("h3", null, displayText(card.heading || "Your agent wants to act")));
      var dest = el("div", "q");
      dest.appendChild(el("div", "qh", "Where it goes"));
      dest.appendChild(el("span", "mono", displayText(card.destination || "")));
      box.appendChild(dest);
      var q = el("div", "q");
      q.appendChild(el("div", "qh", "The exact thing it would do"));
      var c = card.content;
      if (Array.isArray(c)) {
        c.forEach(function (pair) {
          var line = el("div", "cvrow");
          if (Array.isArray(pair) && pair.length >= 2) {
            line.appendChild(el("span", "cvk", displayText(String(pair[0])) + ": "));
            line.appendChild(el("span", "mono cvv", displayText(String(pair[1]))));
          } else {
            line.appendChild(el("span", "mono cvv", displayText(String(pair))));
          }
          q.appendChild(line);
        });
      } else {
        q.appendChild(el("span", "mono", displayText(c == null ? "" : String(c))));
      }
      box.appendChild(q);
      var f = el("div", "field");
      f.appendChild(el("label", null, "Your passphrase, to approve this one action"));
      var pw = el("input", "input"); pw.id = "approvepw"; pw.type = "password"; pw.autocomplete = "off";
      pw.setAttribute("data-lpignore", "true"); pw.placeholder = "Passphrase";
      f.appendChild(pw); box.appendChild(f);
      var btns = el("div", "btnrow");
      var ap = el("button", "btn agent", "Approve & sign");
      ap.onclick = function () { approveAction(card, pw, ap); };
      var rj = el("button", "btn ghost", "Reject");
      rj.onclick = function () { rejectAction(card.request_id); };
      btns.appendChild(ap); btns.appendChild(rj); box.appendChild(btns);
      wrap.appendChild(box);
    }).catch(function () {});
  }

  function approveAction(card, pwEl, btn) {
    var pw = pwEl.value || "";
    if (!pw) { toast("Enter your passphrase to approve"); return; }
    if (btn) btn.disabled = true;
    api("POST", "/api/approve", { request_id: card.request_id, commit: card.action_commit, passphrase: pw }).then(function (res) {
      if (res.status === 403) { toast((res.data && res.data.error) || "That passphrase did not unlock your key"); return; }
      if (res.status === 409) { toast((res.data && res.data.error) || "This changed; reloading"); loadPending(); return; }
      if (!res.ok || !res.data.ok) { toast((res.data && res.data.error) || "Could not approve"); return; }
      loadPending(); loadFeed(); toast("Approved and signed");
    }).catch(function () { toast("The local server did not respond"); })
      .then(function () {
        pwEl.value = "";
        if (btn) btn.disabled = false;
      });
  }

  function rejectAction(rid) {
    api("POST", "/api/pending/reject", { request_id: rid }).then(function (res) {
      if (!res.ok) { toast((res.data && res.data.error) || "Could not reject"); return; }
      loadPending(); toast("Rejected");
    }).catch(function () { toast("The local server did not respond"); });
  }

  document.querySelectorAll("#durpicks button[data-secs]").forEach(function (b) {
    b.onclick = function () { selectDur(parseInt(b.getAttribute("data-secs"), 10), b); };
  });
  var defDur = document.querySelector('#durpicks button[data-secs="900"]');
  if (defDur) defDur.classList.add("on");
  var durc = document.getElementById("durcustom");
  if (durc) durc.addEventListener("input", function () {
    document.querySelectorAll("#durpicks button").forEach(function (b) { b.classList.remove("on"); });
  });
  document.querySelectorAll("#themepicks button[data-theme]").forEach(function (b) {
    b.onclick = function () { setTheme(b.getAttribute("data-theme")); };
  });

  api("GET", "/api/status").then(function (res) {
    var d = res.data || {};
    if (d.has_key) { routeIn(d); return; }
    if (d.stranded) {
      var b = document.getElementById("stranded-banner");
      b.textContent = "A key file was found here, but its public record is missing, so this is not a clean " +
        "first run. Restore owner.json next to owner.pem, or move owner.pem aside, before creating a new key.";
      b.classList.remove("hidden");
    }
    document.getElementById("setup").classList.remove("hidden");
  }).catch(function () {
    document.getElementById("setup").classList.remove("hidden");
  });
})();
