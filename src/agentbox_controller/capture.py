"""One execution's `events.jsonl` (contracts/v1 `agentbox.event.v1`):
host-assigned sequence, fixed event types, guest output as untrusted
base64, within the run's log budget.

```text
budget = record.log_bytes; RESERVE kept for the closing records, and with
an acquisition lane its LANE_RESERVE kept from ordinary records
over budget: the record is dropped and counted; `host.capture.gap` last
```

Never an argv, environment value, path or tool text: fixed codes and
counters only, guest bytes as data. Written only by this process, append
only, synced at the end.
"""
import base64
import json
import os
import time

SCHEMA = "agentbox.event.v1"
RESERVE = 4096
SEVERITY = {"debug": (5, "DEBUG"), "info": (9, "INFO"), "warn": (13, "WARN"), "error": (17, "ERROR")}
ORIGINS = ("host.cli", "host.supervisor", "host.broker", "guest")


class Capture:
    def __init__(self, log_dir_fd, run_id, execution_id, budget, lane_reserve=0):
        self.fd = os.open("events.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND
                          | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=log_dir_fd)
        self.run_id, self.execution_id = run_id, execution_id
        self.budget = budget
        self.lane_reserve = lane_reserve
        self.written = 0
        self.seq = 0
        self.dropped_bytes = 0
        self.dropped_records = 0
        self.failed = False
        self.closed = False

    def record(self, origin, event_type, severity="info", attributes=None, body=None, closing=False, lane=False):
        if self.closed or origin not in ORIGINS:
            return False
        number, text = SEVERITY[severity]
        value = {"schema": SCHEMA, "seq": self.seq + 1, "time_unix_nano": str(time.time_ns()),
                 "run_id": self.run_id, "execution_id": self.execution_id, "origin": origin,
                 "event_type": event_type, "severity_number": number, "severity_text": text,
                 "attributes": dict(attributes or {})}
        if body is not None:
            value["body"] = base64.b64encode(body).decode()
            value["body_encoding"] = "base64"
        line = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        limit = self.budget if closing else self.budget - RESERVE - (0 if lane else self.lane_reserve)
        if self.failed or self.written + len(line) > limit:
            self.dropped_records += 1
            self.dropped_bytes += len(body or b"")
            return False
        try:
            os.write(self.fd, line)
        except OSError:
            self.failed = True
            return False
        self.seq += 1
        self.written += len(line)
        return True

    def close(self):
        """The gap record, if anything was lost, then synced and closed;
        True only if every record was kept."""
        if self.closed:
            return not self.failed
        if self.dropped_records:
            self.record("host.supervisor", "host.capture.gap", "warn",
                        {"dropped_bytes": self.dropped_bytes, "dropped_records": self.dropped_records},
                        closing=True)
        complete = not self.failed and self.dropped_records == 0
        try:
            os.fsync(self.fd)
        except OSError:
            complete = False
        os.close(self.fd)
        self.closed = True
        return complete
