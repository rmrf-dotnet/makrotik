/* ==========================================================================
   Makrotik Share — client behaviour
   ========================================================================== */
(function () {
  "use strict";

  var MAX_BYTES = window.MAKROTIK_MAX_BYTES || 200 * 1024 * 1024 * 1024; // 200 GB fallback

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  function csrfToken() {
    var el = $("#upload-form input[name='csrf_token']") ||
      $("#delete-form input[name='csrf_token']");
    return el ? el.value : "";
  }

  function humanSize(bytes) {
    if (!bytes) return "0 B";
    var units = ["B", "KB", "MB", "GB", "TB"];
    var i = 0;
    var n = bytes;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
    return (i === 0 ? n : n.toFixed(1)) + " " + units[i];
  }

  /* ── Toasts ── */
  function toast(message, danger) {
    var stack = $("#toast-stack");
    if (!stack) return;
    var el = document.createElement("div");
    el.className = "toast" + (danger ? " is-danger" : "");
    el.innerHTML =
      (danger
        ? '<svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="7" cy="7" r="5.5"/><path d="M7 4.5v3.5M7 10v.5"/></svg>'
        : '<svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2.5 7.5l3 3 6-6.5"/></svg>');
    var span = document.createElement("span");
    span.textContent = message;
    el.appendChild(span);
    stack.appendChild(el);
    requestAnimationFrame(function () { el.classList.add("is-visible"); });
    setTimeout(function () {
      el.classList.remove("is-visible");
      setTimeout(function () { el.remove(); }, 250);
    }, 2600);
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        ta.remove();
        resolve();
      } catch (err) { reject(err); }
    });
  }

  /* ── Copy-link buttons (share page + recent rows in dashboard) ── */
  function bindCopyButtons(root) {
    $$(".copy-link[data-url], [data-url]", root).forEach(function (btn) {
      btn.addEventListener("click", function () {
        copyText(btn.getAttribute("data-url"))
          .then(function () { toast("Link copied to clipboard"); })
          .catch(function () { toast("Could not copy link", true); });
      });
    });
  }
  bindCopyButtons(document);

  /* ── Expiry picker ── */
  window.pickExpiry = function (btn) {
    $$("#expiry-nav .nav-item").forEach(function (b) { b.classList.remove("is-active"); });
    btn.classList.add("is-active");
    var input = $("#expiry-input");
    if (input) input.value = btn.getAttribute("data-expiry");
  };

  /* ── Upload form ──
     Uploads stream via XHR so the UI can show real progress and speed, even
     for very large files. */
  var form = $("#upload-form");
  if (form) {
    var input = $("#file-input");
    var dropzone = $("#dropzone");
    var selected = $("#selected-file");
    var selectedName = $("#selected-name");
    var selectedSize = $("#selected-size");
    var selectedFiles = $("#selected-files");
    var selectedFilesBody = $("#selected-files-body");
    var clearBtn = $("#clear-file");
    var submitBtn = $("#submit-btn");
    var hint = $("#form-hint");
    var progress = $("#progress");
    var progressFill = $("#progress-fill");
    var progressText = $("#progress-text");
    var progressPct = $("#progress-pct");
    var progressSpeed = $("#progress-speed");
    var progressEta = $("#progress-eta");
    var resultSection = $("#result-section");

    var currentFiles = [];
    var startedAt = 0;

    function setHint(text) { if (hint) hint.textContent = text; }

    function fileKey(file) {
      return file.name + "\u0000" + file.size + "\u0000" + file.lastModified;
    }

    function applyFiles(files) {
      var list = Array.prototype.slice.call(files || []);
      var existing = currentFiles.map(fileKey);
      var added = 0;
      list.forEach(function (file) {
        if (!file) return;
        if (file.size > MAX_BYTES) {
          toast(file.name + " exceeds the " + humanSize(MAX_BYTES) + " limit", true);
          return;
        }
        var key = fileKey(file);
        if (existing.indexOf(key) !== -1) return;
        currentFiles.push(file);
        existing.push(key);
        added += 1;
      });

      if (!currentFiles.length) {
        clearFiles();
        input.value = "";
        return;
      }

      var total = currentFiles.reduce(function (sum, file) { return sum + file.size; }, 0);
      if (selectedFilesBody) {
        selectedFilesBody.innerHTML = "";
        currentFiles.forEach(function (file) {
          var row = document.createElement("tr");
          var nameCell = document.createElement("td");
          nameCell.className = "upload-file-name";
          nameCell.textContent = file.name;
          var sizeCell = document.createElement("td");
          sizeCell.textContent = humanSize(file.size);
          var statusCell = document.createElement("td");
          statusCell.className = "upload-file-status";
          statusCell.textContent = "Queued";
          row.appendChild(nameCell);
          row.appendChild(sizeCell);
          row.appendChild(statusCell);
          selectedFilesBody.appendChild(row);
        });
      }
      if (selectedFiles) selectedFiles.hidden = false;
      if (currentFiles.length === 1) {
        selectedName.textContent = currentFiles[0].name;
        selectedSize.textContent = humanSize(currentFiles[0].size);
      } else {
        selectedName.textContent = currentFiles.length + " files selected";
        selectedSize.textContent = humanSize(total) + " total";
      }
      selected.hidden = false;
      dropzone.hidden = true;
      submitBtn.disabled = false;
      setHint("Ready to upload " + currentFiles.length + " file" + (currentFiles.length === 1 ? "" : "s") +
        (added ? " (" + added + " added)" : ""));
      input.value = "";
    }

    function applyFile(file) { applyFiles(file ? [file] : []); }

    function clearFiles() {
      currentFiles = [];
      input.value = "";
      selected.hidden = true;
      if (selectedFiles) selectedFiles.hidden = true;
      if (selectedFilesBody) selectedFilesBody.innerHTML = "";
      dropzone.hidden = false;
      submitBtn.disabled = true;
      setHint("Choose one or more files to continue");
    }

    function clearFile() { clearFiles(); }

    input.addEventListener("change", function () {
      if (input.files && input.files.length) applyFiles(input.files);
    });

    clearBtn.addEventListener("click", clearFile);
    var addMoreBtn = $("#add-more-files");
    if (addMoreBtn) {
      addMoreBtn.addEventListener("click", function () { input.click(); });
    }
    if (selected) {
      ["dragenter", "dragover"].forEach(function (evt) {
        selected.addEventListener(evt, function (e) {
          e.preventDefault();
          selected.classList.add("is-dragover");
        });
      });
      ["dragleave", "drop"].forEach(function (evt) {
        selected.addEventListener(evt, function (e) {
          e.preventDefault();
          selected.classList.remove("is-dragover");
        });
      });
      selected.addEventListener("drop", function (e) {
        e.preventDefault();
        e.stopPropagation();
        selected.classList.remove("is-dragover");
        var dt = e.dataTransfer;
        if (dt && dt.files && dt.files.length) applyFiles(dt.files);
      });
    }

    if (form) {
      ["dragenter", "dragover"].forEach(function (evt) {
        form.addEventListener(evt, function (e) {
          e.preventDefault();
          form.classList.add("is-dragover");
        });
      });
      ["dragleave", "drop"].forEach(function (evt) {
        form.addEventListener(evt, function (e) {
          e.preventDefault();
          form.classList.remove("is-dragover");
        });
      });
      form.addEventListener("drop", function (e) {
        e.preventDefault();
        form.classList.remove("is-dragover");
        var dt = e.dataTransfer;
        if (dt && dt.files && dt.files.length) applyFiles(dt.files);
      });
    }

    ["dragenter", "dragover"].forEach(function (evt) {
      dropzone.addEventListener(evt, function (e) {
        e.preventDefault();
        dropzone.classList.add("is-dragover");
      });
    });
    ["dragleave", "drop"].forEach(function (evt) {
      dropzone.addEventListener(evt, function (e) {
        e.preventDefault();
        dropzone.classList.remove("is-dragover");
      });
    });
    dropzone.addEventListener("drop", function (e) {
      var dt = e.dataTransfer;
      if (dt && dt.files && dt.files.length) applyFiles(dt.files);
    });

    document.addEventListener("dragover", function (e) { e.preventDefault(); });
    document.addEventListener("drop", function (e) { e.preventDefault(); });

    function uploadOne(file, onProgress) {
      return new Promise(function (resolve, reject) {
        var data = new FormData();
        data.append("file", file);
        data.append("expiry", $("#expiry-input").value);
        data.append("csrf_token", csrfToken());

        var xhr = new XMLHttpRequest();
        xhr.open("POST", "/upload", true);
        xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
        if (csrfToken()) xhr.setRequestHeader("X-CSRF-Token", csrfToken());

        xhr.upload.addEventListener("progress", function (evt) {
          if (!evt.lengthComputable) return;
          var elapsed = (Date.now() - startedAt) / 1000;
          var pct = Math.round((evt.loaded / evt.total) * 100);
          var speed = evt.loaded / (elapsed || 1);
          progressFill.style.width = pct + "%";
          progressPct.textContent = pct + "%";
          progressSpeed.textContent = humanSize(speed) + "/s";
          if (pct < 100 && speed > 0) {
            var remaining = Math.round((evt.total - evt.loaded) / speed);
            progressEta.textContent = "≈ " + formatEta(remaining);
          } else {
            progressEta.textContent = "finalizing…";
          }
          if (pct >= 100) progressText.textContent = "Storing on disk…";
          if (typeof onProgress === "function") onProgress(pct);
        });

        xhr.addEventListener("load", function () {
          var res = null;
          try { res = JSON.parse(xhr.responseText); } catch (err) { res = null; }
          if (xhr.status >= 200 && xhr.status < 300 && res && res.share_url) {
            resolve(res);
          } else {
            reject(new Error((res && res.error) || "Upload failed. Please try again."));
          }
        });

        xhr.addEventListener("error", function () {
          reject(new Error("Network error during upload"));
        });

        xhr.send(data);
      });
    }

    function formatEta(secs) {
      if (secs < 60) return secs + "s";
      var m = Math.floor(secs / 60);
      var s = secs % 60;
      return m + "m " + s + "s";
    }

    function appendResult(res) {
      var list = $("#results-list");
      if (!list) return;
      var row = document.createElement("div");
      row.className = "recent-row result-row";

      var icon = document.createElement("div");
      icon.className = "recent-icon";
      icon.innerHTML = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8.5 2H4a1.5 1.5 0 0 0-1.5 1.5v9A1.5 1.5 0 0 0 4 14h8a1.5 1.5 0 0 0 1.5-1.5V6.5L8.5 2z" /><path d="M8.5 2v4.5H13" /></svg>';
      row.appendChild(icon);

      var meta = document.createElement("div");
      meta.className = "recent-meta";
      var name = document.createElement("a");
      name.className = "recent-name";
      name.href = res.share_url;
      name.target = "_blank";
      name.rel = "noopener";
      name.textContent = res.name;
      meta.appendChild(name);
      var sub = document.createElement("div");
      sub.className = "recent-sub";
      sub.textContent = res.size_human + " · " + res.downloads + " download" + (res.downloads === 1 ? "" : "s");
      meta.appendChild(sub);
      row.appendChild(meta);

      var actions = document.createElement("div");
      actions.className = "recent-actions";

      var copyBtn = document.createElement("button");
      copyBtn.className = "btn-icon copy-link";
      copyBtn.type = "button";
      copyBtn.title = "Copy link";
      copyBtn.setAttribute("aria-label", "Copy link");
      copyBtn.setAttribute("data-url", res.share_url);
      copyBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 15 15" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><rect x="5" y="5" width="7" height="7" rx="1.5" /><path d="M3 10V3h7" /></svg>';
      copyBtn.addEventListener("click", function () {
        copyText(res.share_url)
          .then(function () { toast("Link copied to clipboard"); })
          .catch(function () { toast("Could not copy link", true); });
      });
      actions.appendChild(copyBtn);

      var openLink = document.createElement("a");
      openLink.className = "btn-icon";
      openLink.href = res.share_url;
      openLink.target = "_blank";
      openLink.rel = "noopener";
      openLink.title = "Open";
      openLink.setAttribute("aria-label", "Open");
      openLink.innerHTML = '<svg width="14" height="14" viewBox="0 0 15 15" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 3H3.5A1.5 1.5 0 0 0 2 4.5v7A1.5 1.5 0 0 0 3.5 13h7A1.5 1.5 0 0 0 12 11.5V9" /><path d="M9 2h4v4M13 2L6.5 8.5" /></svg>';
      actions.appendChild(openLink);

      var deleteLink = document.createElement("a");
      deleteLink.className = "btn-icon";
      deleteLink.href = res.delete_url;
      deleteLink.title = "Delete now";
      deleteLink.setAttribute("aria-label", "Delete now");
      deleteLink.innerHTML = '<svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M2.5 3.5h9M5 3.5V2h4v1.5M4.5 3.5l.5 8h5l.5-8" /></svg>';
      actions.appendChild(deleteLink);

      row.appendChild(actions);
      list.appendChild(row);
      resultSection.hidden = false;
    }

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      if (!currentFiles.length) return;

      var files = currentFiles.slice();
      var totalFiles = files.length;
      var completed = 0;
      var failed = 0;

      submitBtn.disabled = true;
      selected.style.opacity = "0.6";
      clearBtn.disabled = true;
      progress.hidden = false;
      progressText.textContent = "Uploading…";
      progressPct.textContent = "0%";
      progressSpeed.textContent = "";
      progressEta.textContent = "";
      progressFill.style.width = "0%";
      setHint("Keep this tab open while the files upload");

      function next(index) {
        if (index >= files.length) {
          progress.hidden = true;
          progressFill.style.width = "0%";
          selected.style.opacity = "1";
          clearBtn.disabled = false;
          clearFiles();
          var summary = completed + " of " + totalFiles + " file" + (totalFiles === 1 ? "" : "s") + " uploaded";
          if (failed) summary += " (" + failed + " failed)";
          setHint(summary);
          if (completed) {
            toast(summary);
            resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
          }
          return;
        }

        var file = files[index];
        var statusCell = selectedFilesBody && selectedFilesBody.children[index]
          ? selectedFilesBody.children[index].querySelector(".upload-file-status")
          : null;
        if (statusCell) statusCell.textContent = "Uploading 0%";
        startedAt = Date.now();
        progressText.textContent = "Uploading " + file.name + "…";
        progressPct.textContent = "0%";
        setHint("Uploading " + (index + 1) + " of " + totalFiles + ": " + file.name);

        uploadOne(file, function (pct) {
          if (statusCell) statusCell.textContent = "Uploading " + pct + "%";
        }).then(function (res) {
          completed += 1;
          if (statusCell) statusCell.textContent = "Done";
          appendResult(res);
        }).catch(function (err) {
          failed += 1;
          if (statusCell) statusCell.textContent = "Failed";
          toast(err.message || "Upload failed", true);
        }).then(function () {
          next(index + 1);
        });
      }

      next(0);
    });

    function setResultError(msg) {
      toast(msg, true);
    }
  }

  /* ── Delete confirmation modal (My files) ── */
  var modal = $("#delete-modal");
  if (modal) {
    var deleteForm = $("#delete-form");
    var deleteName = $("#delete-modal-name");

    $$(".delete-file").forEach(function (btn) {
      btn.addEventListener("click", function () {
        deleteForm.action = btn.getAttribute("data-delete-url");
        deleteName.textContent = btn.getAttribute("data-name");
        modal.hidden = false;
        document.body.style.overflow = "hidden";
      });
    });

    function closeModal() {
      modal.hidden = true;
      document.body.style.overflow = "";
    }
    $("#delete-cancel").addEventListener("click", closeModal);
    modal.addEventListener("click", function (e) {
      if (e.target === modal) closeModal();
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && !modal.hidden) closeModal();
    });

    /* Submit via fetch so the row disappears without a full reload. */
    deleteForm.addEventListener("submit", function (e) {
      e.preventDefault();
      var url = deleteForm.action;
      var body = new FormData(deleteForm);
      fetch(url, {
        method: "POST",
        headers: { "X-Requested-With": "XMLHttpRequest", "X-CSRF-Token": csrfToken() },
        body: body
      })
        .then(function (r) {
          return r.json().then(function (j) { return { ok: r.ok, json: j, status: r.status }; });
        })
        .then(function (res) {
          if (res.ok) {
            closeModal();
            toast("File removed and safely archived");
            setTimeout(function () { window.location.reload(); }, 400);
          } else {
            closeModal();
            toast((res.json && res.json.error) || "Could not delete file", true);
          }
        })
        .catch(function () {
          closeModal();
          toast("Could not delete file", true);
        });
    });
  }
})();