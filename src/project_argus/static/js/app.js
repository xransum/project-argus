/**
 * Project Argus — API Dashboard
 *
 * One form per tab (URL / Domain / IP).
 * A <select> chooses which action to run; the textarea collects the targets.
 * Submitting POSTs to the chosen endpoint, then auto-polls the job until
 * completion and renders the JSON result.
 */

(function ($) {
    "use strict";

    // -----------------------------------------------------------------------
    // jQuery UI tabs — restore last active tab
    // -----------------------------------------------------------------------

    $("#api-tabs").tabs({
        active: parseInt(sessionStorage.getItem("argus-tab") || "0", 10),
        activate: function (_e, ui) {
            sessionStorage.setItem("argus-tab", ui.newTab.index());
            // Sync the description when switching tabs
            syncDesc(ui.newPanel);
        }
    });

    // -----------------------------------------------------------------------
    // Per-tab endpoint metadata
    // Read the <script type="application/json" class="ep-data"> block that
    // the Jinja template embeds inside each tab panel.
    // -----------------------------------------------------------------------

    function epData($panel) {
        try {
            return JSON.parse($panel.find("script.ep-data").text());
        } catch (_) {
            return {};
        }
    }

    // -----------------------------------------------------------------------
    // Sync the description paragraph + placeholder when the select changes
    // -----------------------------------------------------------------------

    function syncDesc($panel) {
        var data   = epData($panel);
        var action = $panel.find(".action-select").val();
        var meta   = data[action] || {};

        $panel.find(".action-desc").text(meta.desc || "");
        $panel.find(".query-input").attr("placeholder", meta.placeholder || "");
        $panel.find(".action-path").text(meta.path || "");
    }

    // Initialise all panels on page load
    $("#api-tabs .ui-tabs-panel").each(function () {
        syncDesc($(this));
    });

    // Also sync whenever the user changes the select
    $(document).on("change", ".action-select", function () {
        syncDesc($(this).closest(".ui-tabs-panel"));
    });

    // -----------------------------------------------------------------------
    // JSON syntax highlighter
    // -----------------------------------------------------------------------

    function highlightJson(value) {
        var json = typeof value === "string" ? value : JSON.stringify(value, null, 2);

        json = json
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;");

        return json.replace(
            /("(\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
            function (match) {
                var cls = "json-number";
                if (/^"/.test(match)) {
                    cls = /:$/.test(match) ? "json-key" : "json-string";
                } else if (/true|false/.test(match)) {
                    cls = "json-bool";
                } else if (/null/.test(match)) {
                    cls = "json-null";
                }
                return '<span class="' + cls + '">' + match + "</span>";
            }
        );
    }

    // -----------------------------------------------------------------------
    // Result panel helpers
    // -----------------------------------------------------------------------

    /** Show the result panel in a loading / submitted state */
    function showLoading($panel, statusCode, elapsed) {
        var $result = $panel.find(".result-panel");
        var $badge  = $result.find(".status-badge");
        var $time   = $result.find(".response-time");

        if (statusCode) {
            var cls = statusCode < 300 ? "ok" : statusCode < 500 ? "warn" : "err";
            $badge.attr("class", "status-badge " + cls).text(statusCode);
        } else {
            $badge.attr("class", "status-badge").text("");
        }
        $time.text(elapsed ? elapsed + " ms" : "");

        $result.find(".job-banner").show();
        $result.find(".response-body").hide().empty();
        $result.show();
    }

    /** Populate the job banner fields */
    function updateBanner($panel, jobId, state, countdown) {
        var $banner = $panel.find(".job-banner");
        if (jobId)    $banner.find(".job-id").text(jobId);
        if (state)    $banner.find(".job-state").attr("class", "job-state " + state).text(state);
        if (countdown !== undefined) $banner.find(".poll-countdown").text(countdown);
    }

    /** Hide the banner and show the final JSON */
    function showResult($panel, data) {
        var $result = $panel.find(".result-panel");
        $result.find(".job-banner").hide();
        var $body = $result.find(".response-body");
        $body.html(highlightJson(data)).show();
    }

    /** Hide the entire result panel */
    function hideResult($panel) {
        $panel.find(".result-panel").hide();
        $panel.find(".job-banner").hide();
        $panel.find(".response-body").hide().empty();
    }

    // -----------------------------------------------------------------------
    // Auto-poll
    // -----------------------------------------------------------------------

    var POLL_INTERVAL = 4; // seconds

    function startAutoPoll($panel, jobId) {
        var remaining = POLL_INTERVAL;
        var timerId;

        function tick() {
            remaining -= 1;
            if (remaining <= 0) {
                updateBanner($panel, null, null, "checking…");
                clearInterval(timerId);
                doPoll();
            } else {
                updateBanner($panel, null, null, "next check in " + remaining + "s");
            }
        }

        function doPoll() {
            $.ajax({
                url:      "/jobs/" + jobId + "/status",
                method:   "GET",
                dataType: "json",
                timeout:  10000
            })
            .done(function (data) {
                var state = (data.status || "unknown").toLowerCase();
                updateBanner($panel, null, state, "");

                if (state === "completed" || state === "failed") {
                    fetchResults($panel, jobId);
                } else {
                    remaining = POLL_INTERVAL;
                    timerId   = setInterval(tick, 1000);
                }
            })
            .fail(function () {
                updateBanner($panel, null, "error", "retrying…");
                remaining = POLL_INTERVAL;
                timerId   = setInterval(tick, 1000);
            });
        }

        updateBanner($panel, jobId, "pending", "next check in " + remaining + "s");
        timerId = setInterval(tick, 1000);
    }

    function fetchResults($panel, jobId) {
        $.ajax({
            url:      "/jobs/" + jobId + "/results",
            method:   "GET",
            dataType: "json",
            timeout:  15000
        })
        .done(function (data) {
            showResult($panel, data);
        })
        .fail(function (xhr) {
            var detail;
            try { detail = JSON.parse(xhr.responseText); }
            catch (_) { detail = { error: "Failed to fetch results" }; }
            showResult($panel, detail);
        });
    }

    // -----------------------------------------------------------------------
    // Run button — submit
    // -----------------------------------------------------------------------

    $(document).on("click", ".btn-run", function () {
        var $btn    = $(this);
        var $panel  = $btn.closest(".ui-tabs-panel");
        var data    = epData($panel);
        var action  = $panel.find(".action-select").val();
        var meta    = data[action] || {};
        var path    = meta.path;
        var param   = meta.param;

        if (!path) return;

        // Build the values array from the textarea
        var raw    = $panel.find(".query-input").val().trim();
        var values = raw
            .split(/[\n,]+/)
            .map(function (s) { return s.trim(); })
            .filter(function (s) { return s !== ""; });

        if (values.length === 0) {
            $panel.find(".query-input").focus();
            return;
        }

        var payload = {};
        payload[param] = values;

        $btn.prop("disabled", true);
        showLoading($panel, null, null);
        updateBanner($panel, "…", "pending", "submitting…");

        var t0 = performance.now();

        $.ajax({
            url:         path,
            method:      "POST",
            contentType: "application/json",
            data:        JSON.stringify(payload),
            dataType:    "json",
            timeout:     30000
        })
        .done(function (resp, _status, xhr) {
            var elapsed = Math.round(performance.now() - t0);
            var code    = xhr.status;
            showLoading($panel, code, elapsed);

            var jobId = resp && resp.job_id;
            if (jobId) {
                // Async job — poll until done
                startAutoPoll($panel, jobId);
            } else {
                // Synchronous response — show immediately
                showResult($panel, resp);
            }
        })
        .fail(function (xhr) {
            var elapsed = Math.round(performance.now() - t0);
            var code    = xhr.status || 0;
            var detail;
            try { detail = JSON.parse(xhr.responseText); }
            catch (_) { detail = { error: xhr.statusText || "Network error" }; }

            showLoading($panel, code, elapsed);
            showResult($panel, detail);
        })
        .always(function () {
            $btn.prop("disabled", false);
        });
    });

    // -----------------------------------------------------------------------
    // Clear / dismiss button
    // -----------------------------------------------------------------------

    $(document).on("click", ".btn-clear", function () {
        hideResult($(this).closest(".ui-tabs-panel"));
    });

}(jQuery));
