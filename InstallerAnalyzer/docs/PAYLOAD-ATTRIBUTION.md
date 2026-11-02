# Payload writer observations

Sandbox analysis now includes best-effort Windows kernel file tracing alongside process-tree and connection observations. This is enabled during discovery and does not change Windows security policy or install a driver. Collection failures are recorded as unavailable or partial and do not invalidate an independently completed installer lifecycle.

A completed-write observation binds a file path, successful I/O completion and issuing thread to an observed installer process lifetime. It retains the first completed write byte count, timestamp, process identity and explanatory evidence. It can preserve evidence for temporary files removed before the final directory scan. It does not establish who originally created every file, the total file size, its content, a download source, or a need for Internet access.

Intelligence displays writer details and measured process-to-payload graph edges. payload-file-activity.json is included in diagnostic exports. Process birth and observation times also accompany connection observations, allowing a file writer to be labelled network-active only when the same process lifetime was observed. This label is a candidate correlation, not verified download attribution. Command-line download output references remain explicitly unverified.

Raw ETL stays inside the disposable Sandbox and is not exported. Capture is bounded to 128 MB, parsing to 300,000 events/14 seconds, filtered file observations to 256, and the foreground wait to 20 seconds. Unsupported paths, missed events, limits and timeouts remain unknown. File contents, network payloads and remote endpoints are not exported by this collector. Existing diagnostic redaction applies during export, and AI remains off by default and read-only when enabled.

Original source installers remain the deployment source. No prerequisite provisioning or automatic execution of newly traced payloads is added.