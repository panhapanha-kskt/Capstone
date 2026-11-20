#!/usr/bin/env python3
"""Learner service (Part 2): start a training run only on one of the three triggers, one at a time.

    python3 scripts/learner.py                  # loop forever (normally started by scripts/soc.sh up)
    python3 scripts/learner.py --once           # one evaluation, then exit (debugging)
    python3 scripts/learner.py --auto-promote   # promote on gate PASS (default: stop at "ready to promote")

Triggers (config/soc.yaml `triggers:`), priority (b) > (c) > (a):
  (b) captures  new files in data/processed/week7 listed in SHA256SUMS, checksum OK, settled, not trained yet
                → nice bash scripts/train_new_data.sh data/processed/week7
  (c) verdicts  >= 50 settled analyst verdicts newer than the last training run
                → scripts/export_feedback_labels.py, then FEEDBACK=<file> nice bash scripts/run_candidate_seeds.sh
  (a) drift     3 distinct consecutive monitoring reports with retrain_recommended (edge-triggered) AND
                something new to train on (require_new_data) → the (b) or (c) command for what is new
Gates: cooldown after every run, max runs per day, runs/soc/learner.lock, runs/.promote.lock, and no
train_models.sh started by someone else. Every decision is one JSON line with "source": "learner" in
runs/promotion_log.jsonl (idle polls are not logged).

The learner only ever runs the commands in ALLOWED_SCRIPTS. It never writes to models/: promotion is
scripts/part_b.py's job (gate → promote_model.sh → smoke test → rollback), and only with auto-promote.
Env overrides (tests / live check): SOC_CONFIG, SOC_TRAIN_CMD (gets --trigger T --run RUN appended),
SOC_EXPORT_CMD, SOC_PART_B_CMD, SOC_NOW (fixed clock, epoch seconds), SOC_AUTO_PROMOTE=1.
"""
import argparse
import contextlib
import datetime
import hashlib
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows: run the learner under WSL
    fcntl = None

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from dns_detect.soc import config as soc_config  # noqa: E402
from dns_detect.soc import triggers as T  # noqa: E402

# The only repo scripts the learner may run. train_models.sh / promote_model.sh / rollback_model.sh are
# reached only through these (seeds → runs/<RUN>_s<seed>, promote only via part_b.py after the gate).
ALLOWED_SCRIPTS = ("scripts/train_new_data.sh", "scripts/run_candidate_seeds.sh",
                   "scripts/export_feedback_labels.py", "scripts/part_b.py")
FORBIDDEN_SCRIPTS = ("train_models.sh", "promote_model.sh", "rollback_model.sh", "compare_models.py",
                     "smoke_models.py")
TRAIN_ENV_KEYS = ("AUTO_PROMOTE", "FEEDBACK", "RUN_NAME", "SEEDS", "SPLIT", "FILES")
BUSY_DECISION = "not promoted: run_pipeline.sh is running"
BUSY_TEXT = "another Part B run"


class NotAllowed(RuntimeError):
    pass


def check_allowed(argv):
    """Refuse any command that names a repo script outside ALLOWED_SCRIPTS (test-enforced allowlist)."""
    allowed = {Path(x).name for x in ALLOWED_SCRIPTS}
    scripts_dir = (ROOT / "scripts").resolve()
    for a in argv:
        s = str(a)
        name = Path(s).name
        if name in FORBIDDEN_SCRIPTS:
            raise NotAllowed(f"learner may not run {s}")
        p = Path(s) if Path(s).is_absolute() else ROOT / s
        if name.endswith((".sh", ".py")) and p.parent.resolve() == scripts_dir and name not in allowed:
            raise NotAllowed(f"learner may not run {s}")
    return argv


def git_commit():
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True,
                              timeout=10).stdout.strip() or None
    except Exception:
        return None


def hash_models(models_dir):
    """sha256 over every file under models/ except models/archive/ (archived sets are moved, not edited)."""
    h = hashlib.sha256()
    root = Path(models_dir)
    if not root.is_dir():
        return None
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if rel.split("/", 1)[0] == "archive" or not p.is_file():
            continue
        h.update(rel.encode() + b"\0" + T.sha256_file(p).encode() + b"\n")
    return h.hexdigest()


def lock_busy(path):
    """True if someone holds an flock on path (probe only; the file is created if missing)."""
    if fcntl is None:
        return False
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(f, fcntl.LOCK_UN)
    return False


def foreign_training(own_pgid=None):
    """PIDs of train_models.sh processes that are not in the learner's own process group."""
    own = os.getpgrp() if own_pgid is None else own_pgid
    out = []
    for d in Path("/proc").glob("[0-9]*"):
        try:
            cmd = (d / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")
            if "train_models.sh" in cmd and os.getpgid(int(d.name)) != own:
                out.append(int(d.name))
        except (OSError, ValueError):
            continue
    return out


_IONICE = None


def priority_prefix(cfg):
    """nice -n 10 [ionice -c 3]: ionice only if it works here (it is probably a no-op on /mnt/c under WSL)."""
    global _IONICE
    tp = cfg.get("training_priority") or {}
    pre = []
    if shutil.which("nice") and int(tp.get("nice") or 0) > 0:
        pre = ["nice", "-n", str(int(tp["nice"]))]
    cls = tp.get("ionice_class")
    if cls is not None and shutil.which("ionice"):
        if _IONICE is None:
            try:
                _IONICE = subprocess.run(["ionice", "-c", str(cls), "true"], capture_output=True,
                                         timeout=10).returncode == 0
            except Exception:
                _IONICE = False
        if _IONICE:
            pre += ["ionice", "-c", str(cls)]
    return pre


def python_env(cfg, base=None):
    """Environment with the configured Python's bin/ first on PATH (the Part B scripts call python3)."""
    env = dict(os.environ if base is None else base)
    bindir = os.path.dirname(cfg["_python"])
    if bindir:
        env["PATH"] = bindir + os.pathsep + env.get("PATH", "")
        if (Path(bindir).parent / "pyvenv.cfg").is_file():
            env["VIRTUAL_ENV"] = str(Path(bindir).parent)
    env["PYTHONUNBUFFERED"] = "1"
    return env


def hash_models_all(dirs):
    return "+".join(str(hash_models(d)) for d in dirs)


class Learner:
    def __init__(self, cfg, auto_promote=False, clock=None, out=None):
        self.cfg = cfg
        self.sd = soc_config.state_dir(cfg)
        self.ld = soc_config.log_dir(cfg)
        self.runs_dir = soc_config.rpath(cfg["paths"]["runs_dir"])
        self.models_dir = soc_config.rpath(cfg["paths"]["models_dir"])
        # The hash guard watches the configured folder AND <repo>/models, the folder part_b.py /
        # promote_model.sh really write, so a demo config pointing elsewhere cannot blind it.
        self.guard_dirs = [self.models_dir]
        if self.models_dir.resolve() != (ROOT / "models").resolve():
            self.guard_dirs.append(ROOT / "models")
        self.state_path = self.sd / "learner_state.json"
        self.heartbeat = self.sd / "learner.heartbeat"
        self.lock_path = self.sd / "learner.lock"
        # auto-promote only when explicitly asked: CLI flag / SOC_AUTO_PROMOTE=1 (soc.sh up --auto-promote)
        # or `auto_promote: true` (a real boolean) in config/soc.yaml.
        self.auto_promote = bool(auto_promote) or os.environ.get("SOC_AUTO_PROMOTE") == "1" \
            or cfg.get("auto_promote") is True
        self.clock = clock
        self.out = out or sys.stdout
        self.stop = False
        self._git = None
        self.state = None

    # ── basics ───────────────────────────────────────────────────────────────
    def now(self):
        if self.clock is not None:
            return self.clock()
        v = os.environ.get("SOC_NOW")
        return float(v) if v else time.time()

    def say(self, msg):
        stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{stamp}] learner: {msg}", file=self.out, flush=True)

    def beat(self):
        self.sd.mkdir(parents=True, exist_ok=True)
        self.heartbeat.write_text(str(time.time()))

    def git(self):
        if self._git is None:
            self._git = git_commit() or ""
        return self._git or None

    def log(self, event, decision=None, trigger=None, reason=None, run=None, exit=None, **extra):
        """One JSON line, one write(2) with O_APPEND (lines from part_b.py and us never interleave)."""
        row = {"time": T.iso(self.now()), "source": "learner", "event": event, "decision": decision,
               "trigger": trigger, "reason": reason, "run": run, "exit": exit, "git_commit": self.git(), **extra}
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.runs_dir / "promotion_log.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            os.write(fd, (json.dumps(row) + "\n").encode("utf-8"))
        finally:
            os.close(fd)
        self.say(f"{event}: {decision or ''} {('trigger=' + trigger) if trigger else ''} "
                 f"{('run=' + run) if run else ''} {reason or ''}".rstrip())
        return row

    def log_once(self, key, **row):
        logged = self.state.setdefault("logged", {})
        if key in logged:
            return None
        logged[key] = self.now()
        return self.log(**row)

    # ── state ────────────────────────────────────────────────────────────────
    def empty_state(self):
        return {"drift": {"armed": True, "consecutive": 0, "last_report_sha256": None},
                "captures": {"trained": {}},
                "verdicts": {"trained_until": None, "trained_count": 0},
                "last_run": {"run": None, "trigger": None, "started_at": None, "finished_at": None,
                             "exit": None, "outcome": None},
                "cooldown_until": None, "pending_promote": None, "last_ready": None,
                "run_starts": [], "auto_promotions": [], "logged": {}, "last_trigger_seen": None}

    def load_state(self):
        try:
            st = json.loads(self.state_path.read_text(encoding="utf-8"))
            if not isinstance(st, dict):
                raise ValueError("state file is not a JSON object")
            base = self.empty_state()
            base.update(st)
            return base, False
        except (OSError, ValueError):
            return self.empty_state(), True

    def save_state(self):
        self.sd.mkdir(parents=True, exist_ok=True)
        cut = self.now() - 8 * 86400
        self.state["logged"] = {k: v for k, v in self.state.get("logged", {}).items() if v >= cut}
        self.state["run_starts"] = [t for t in self.state.get("run_starts", []) if t >= cut]
        self.state["auto_promotions"] = [t for t in self.state.get("auto_promotions", []) if t >= cut]
        data = json.dumps(self.state, indent=2)
        tmp = self.state_path.with_suffix(".json.tmp")
        tmp.write_text(data, encoding="utf-8")
        try:
            os.replace(tmp, self.state_path)          # atomic
        except OSError:
            self.state_path.write_text(data, encoding="utf-8")

    def seed_state(self):
        """First start: what the live model already learned from must not trigger a run."""
        st = self.empty_state()
        tc = self.cfg["triggers"]
        prov = self.provenance_files() or []
        prov_names = {Path(p).name for p in prov}
        prov_abs = {str(soc_config.rpath(p).resolve()) for p in prov}
        cdir = soc_config.rpath(tc["captures"]["dir"])
        if cdir.is_dir():
            import fnmatch
            for p in sorted(cdir.iterdir()):
                if p.is_file() and fnmatch.fnmatch(p.name, tc["captures"]["pattern"]) and (
                        p.name in prov_names or str(p.resolve()) in prov_abs):
                    st["captures"]["trained"][p.name] = T.sha256_file(p)
        newest = T.newest_verdict_time(T.load_store(soc_config.rpath(tc["verdicts"]["store"])))
        st["verdicts"]["trained_until"] = T.iso(newest) if newest else None
        st["drift"], _ = T.update_drift(st["drift"], soc_config.rpath(tc["drift"]["report"]))
        st["drift"].update(consecutive=0, armed=True)   # the report already on disk does not count
        self.state = st
        self.log("state_seeded", decision="first start",
                 reason=f"{len(st['captures']['trained'])} capture(s) already in training_provenance.json; "
                        f"verdicts counted after {st['verdicts']['trained_until']}")
        self.save_state()

    def startup(self):
        self.state, fresh = self.load_state()
        if fresh:
            self.seed_state()
        lr = self.state.get("last_run") or {}
        if lr.get("started_at") and not lr.get("finished_at") and not lock_busy(self.lock_path):
            now = self.now()
            lr.update(finished_at=now, exit=None, outcome="aborted")
            self.state["cooldown_until"] = now + self.cooldown_s()
            self.log("run_aborted", decision="aborted", trigger=lr.get("trigger"), run=lr.get("run"),
                     reason="learner stopped mid-run; inputs not marked trained, cooldown set")
            self.save_state()

    # ── helpers ──────────────────────────────────────────────────────────────
    def cooldown_s(self):
        return float(self.cfg["cooldown_minutes"]) * 60

    def provenance_files(self):
        p = self.models_dir / "training_provenance.json"
        try:
            return [f["path"] for f in json.loads(p.read_text(encoding="utf-8"))["source_files"]]
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def missing_training_data(self, kind):
        """What the real Part B scripts would stop on (exit 4 / exit 1): checked before starting them."""
        prov = self.provenance_files()
        if prov is None:
            return [str(self.models_dir / "training_provenance.json")]
        missing = [p for p in prov if not soc_config.rpath(p).is_file()]
        if kind != "captures" and not self.cfg["train"].get("split") and \
                not (self.models_dir / "split_manifest.json").is_file():
            missing.append(str(self.models_dir / "split_manifest.json"))
        return missing

    def locked_reason(self):
        if lock_busy(self.lock_path):
            return "runs/soc/learner.lock held (a learner run is in progress)"
        if lock_busy(self.runs_dir / ".promote.lock"):
            return "runs/.promote.lock held (a promote is running)"
        foreign = foreign_training()
        if foreign:
            return f"train_models.sh not started by the learner is running (pid {foreign[0]})"
        return None

    def part_b_line(self, name):
        """Newest part_b.py line (no "source") for this run name."""
        p = self.runs_dir / "promotion_log.jsonl"
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return None
        for line in reversed(lines):
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict) and "source" not in row and row.get("name") == name:
                return row
        return None

    def gate_numbers(self, run):
        try:
            rep = json.loads((self.runs_dir / f"{run}_gate.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        out = {}
        seeds = [s.get("candidate") for s in rep.get("seeds", []) if isinstance(s.get("candidate"), dict)]
        for key in ("fpr", "recall"):
            vals = sorted(c[key] for c in seeds if isinstance(c.get(key), (int, float)))
            if vals:
                out[f"gate_{key}"] = vals[len(vals) // 2]
        if "passed" in rep:
            out["gate_passed"] = rep["passed"]
        return out

    def train_log(self, run):
        self.ld.mkdir(parents=True, exist_ok=True)
        logs = sorted(self.ld.glob("train_*.log"), key=lambda p: p.stat().st_mtime)
        for old in logs[:max(0, len(logs) - int(self.cfg.get("keep_train_logs") or 20) + 1)]:
            with contextlib.suppress(OSError):
                old.unlink()
        return self.ld / f"train_{run}.log"

    # ── commands (all checked against ALLOWED_SCRIPTS) ────────────────────────
    def train_cmd(self, kind, trigger, run):
        pre = priority_prefix(self.cfg)
        override = os.environ.get("SOC_TRAIN_CMD")
        if override:
            return check_allowed(pre + shlex.split(override) + ["--trigger", trigger, "--run", run])
        if kind == "captures":
            cdir = str(soc_config.rpath(self.cfg["triggers"]["captures"]["dir"]))
            return check_allowed(pre + ["bash", str(ROOT / "scripts/train_new_data.sh"), cdir])
        return check_allowed(pre + ["bash", str(ROOT / "scripts/run_candidate_seeds.sh")])

    def export_cmd(self):
        override = os.environ.get("SOC_EXPORT_CMD")
        if override:
            return check_allowed(shlex.split(override))
        return check_allowed([self.cfg["_python"], str(ROOT / "scripts/export_feedback_labels.py"),
                              "--url", self.cfg["triggers"]["verdicts"]["export_url"]])

    def part_b_cmd(self, run, seeds):
        override = os.environ.get("SOC_PART_B_CMD")
        base = shlex.split(override) if override else [self.cfg["_python"], str(ROOT / "scripts/part_b.py")]
        return check_allowed(priority_prefix(self.cfg) + base +
                             ["--name", run, "--seeds", seeds, "--auto-promote"] +
                             (["--shadow"] if self.shadow_enabled() else []))

    def shadow_enabled(self):
        sh = self.cfg.get("shadow")
        return not (isinstance(sh, dict) and sh.get("enabled") is False)

    def train_env(self, run, kind, auto):
        env = python_env(self.cfg)
        for k in TRAIN_ENV_KEYS:
            env.pop(k, None)                       # never inherit AUTO_PROMOTE, FILES, ... from the shell
        env["RUN_NAME"] = run
        env["SEEDS"] = str(self.cfg["train"]["seeds"])
        if self.shadow_enabled():
            env["SHADOW"] = "1"                    # part_b.py --shadow: online check on current traffic
        if kind != "captures" and self.cfg["train"].get("split"):
            env["SPLIT"] = str(soc_config.rpath(self.cfg["train"]["split"]))
        if kind == "verdicts":
            env["FEEDBACK"] = str(soc_config.rpath(self.cfg["triggers"]["verdicts"]["feedback_file"]))
        if auto:
            env["AUTO_PROMOTE"] = "1"
        return env

    def wait_child(self, proc):
        """Wait for a training child, keeping the heartbeat fresh. On stop: TERM, then KILL."""
        last = 0.0
        while True:
            rc = proc.poll()
            if rc is not None:
                return rc
            if time.time() - last > 5:
                self.beat()
                last = time.time()
            if self.stop:
                with contextlib.suppress(OSError):
                    proc.terminate()
                try:
                    return proc.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    return proc.wait()
            time.sleep(0.2)

    def run_logged(self, cmd, env, logf, lock_fd=None):
        with open(logf, "ab") as f:
            f.write(f"\n$ {shlex.join(cmd)}\n".encode())
            f.flush()
            proc = subprocess.Popen(cmd, cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=f,
                                    stderr=subprocess.STDOUT, pass_fds=(lock_fd,) if lock_fd is not None else ())
            return self.wait_child(proc)

    def tail(self, logf, n=8192):
        try:
            with open(logf, "rb") as f:
                f.seek(0, os.SEEK_END)
                f.seek(max(0, f.tell() - n))
                return f.read().decode("utf-8", "replace")
        except OSError:
            return ""

    # ── outcomes ─────────────────────────────────────────────────────────────
    def outcome(self, rc, run, logf, auto):
        pb = self.part_b_line(run)
        busy = rc == 3 and ((pb or {}).get("decision") == BUSY_DECISION or BUSY_TEXT in self.tail(logf))
        if rc == 0:
            return "promoted", pb
        if rc == 10:
            return "ready", pb
        if rc == 1:
            return ("gate_fail" if (pb or {}).get("gate") == "FAIL" else "error"), pb
        if rc == 2:
            return "rolled_back", pb
        if rc == 3 and busy and auto:
            return "promote_busy", pb
        if rc == 4:
            return "data_missing", pb
        if rc == 5:
            return "shadow_fail", pb
        return "error", pb

    def weekly_auto_ok(self, now):
        recent = [t for t in self.state.get("auto_promotions", []) if now - t < 7 * 86400]
        return len(recent) < int(self.cfg.get("max_auto_promotions_per_week") or 0)

    def ready_info(self, run, pb):
        seeds = str(self.cfg["train"]["seeds"])
        info = {"run": run, "time": T.iso(self.now()),
                "command": f'python3 scripts/part_b.py --name {run} --seeds "{seeds}" --auto-promote'}
        if pb and pb.get("chosen"):
            info["promote_command"] = f"bash scripts/promote_model.sh {pb['chosen']}"
        return info

    def check_models(self, h0, outcome, run, trigger):
        h1 = hash_models_all(self.guard_dirs)
        if h0 != h1 and outcome not in ("promoted", "rolled_back"):
            self.log("models_changed_unexpectedly", decision="alert", trigger=trigger, run=run,
                     reason="models/ changed during a learner step that did not promote (outside part_b.py)",
                     models_before=h0, models_after=h1)
        return h1

    # ── one run ──────────────────────────────────────────────────────────────
    def run_training(self, trigger, caps, verds, drift_n):
        st = self.state
        now = self.now()
        stamp = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        run = f"soc_{trigger}_{stamp}"
        kind = "captures" if (trigger == "captures" or (trigger == "drift" and caps)) else \
            "verdicts" if (trigger == "verdicts" or (trigger == "drift" and verds)) else "defaults"
        inputs = {"captures": [c["sha256"] for c in caps] if kind == "captures" else [],
                  "capture_files": [c["name"] for c in caps] if kind == "captures" else [],
                  "verdicts": len(verds) if kind == "verdicts" else 0, "drift_consecutive": drift_n,
                  "train_on": kind}
        if not os.environ.get("SOC_TRAIN_CMD"):
            missing = self.missing_training_data(kind)
            if missing:
                st["cooldown_until"] = now + self.cooldown_s()
                st["last_run"] = {"run": run, "trigger": trigger, "started_at": now, "finished_at": now,
                                  "exit": 4, "outcome": "data_missing"}
                self.log("run_finished", decision="data_missing", trigger=trigger, run=run, exit=4,
                         reason=f"{len(missing)} training file(s) not on this machine; nothing trained, "
                                f"inputs not marked trained, cooldown set", missing=missing[:20], inputs=inputs)
                self.save_state()
                return "data_missing"

        if fcntl is None:
            self.say("needs Linux/WSL (flock)")
            return None
        lockf = open(self.lock_path, "a")
        try:
            fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            lockf.close()
            self.log_once(f"locked:{trigger}:learner.lock", event="skipped", decision="skipped", trigger=trigger,
                          reason="locked: runs/soc/learner.lock held")
            self.save_state()
            return None
        try:
            auto = self.auto_promote and self.weekly_auto_ok(now)
            st["last_run"] = {"run": run, "trigger": trigger, "started_at": now, "finished_at": None,
                              "exit": None, "outcome": None}
            st["run_starts"].append(now)
            self.save_state()
            if trigger == "drift":
                st["drift"]["armed"] = False                   # edge-triggered: fire once per real run
            h0 = hash_models_all(self.guard_dirs)
            logf = self.train_log(run)
            self.log("run_started", decision="training", trigger=trigger, run=run, inputs=inputs,
                     auto_promote=auto, log=str(logf),
                     reason=None if auto or not self.auto_promote else "weekly auto-promote limit reached")
            env = self.train_env(run, kind, auto)
            rc = None
            if kind == "verdicts":
                rc = self.run_logged(self.export_cmd(), python_env(self.cfg), logf)
                if rc != 0 and not self.stop:
                    return self.finish(run, trigger, rc, "export_failed", None, h0, inputs, caps, verds, auto,
                                       reason="export_feedback_labels.py failed (is the dashboard up?)")
            if not self.stop:
                rc = self.run_logged(self.train_cmd(kind, trigger, run), env, logf, lockf.fileno())
            if self.stop:
                st["last_run"].update(finished_at=self.now(), exit=rc, outcome="aborted")
                st["cooldown_until"] = self.now() + self.cooldown_s()
                self.log("run_aborted", decision="aborted", trigger=trigger, run=run, exit=rc,
                         reason="learner stopped mid-run; inputs not marked trained, cooldown set")
                self.check_models(h0, "aborted", run, trigger)
                self.save_state()
                return "aborted"
            outcome, pb = self.outcome(rc, run, logf, auto)
            return self.finish(run, trigger, rc, outcome, pb, h0, inputs, caps, verds, auto)
        finally:
            fcntl.flock(lockf, fcntl.LOCK_UN)
            lockf.close()

    def finish(self, run, trigger, rc, outcome, pb, h0, inputs, caps, verds, auto, reason=None):
        st = self.state
        now = self.now()
        trained = pb is not None or outcome in ("promoted", "ready", "gate_fail", "rolled_back", "promote_busy",
                                                 "shadow_fail")
        if trained:
            if inputs["train_on"] == "captures":
                for c in caps:
                    st["captures"]["trained"][c["name"]] = c["sha256"]
            if inputs["train_on"] == "verdicts" and verds:
                st["verdicts"]["trained_until"] = T.iso(max(t for _, t in verds))
                st["verdicts"]["trained_count"] = st["verdicts"].get("trained_count", 0) + len(verds)
        st["cooldown_until"] = now + self.cooldown_s()
        st["last_run"].update(finished_at=now, exit=rc, outcome=outcome)
        extra = self.gate_numbers(run)
        if outcome == "ready":
            st["last_ready"] = self.ready_info(run, pb)
            extra["promote_command"] = st["last_ready"]["command"]
        if outcome == "promote_busy":
            st["pending_promote"] = {"run": run, "seeds": str(self.cfg["train"]["seeds"]), "attempts": 0,
                                     "next_at": now + float(self.cfg["promote_retry"]["interval_s"]),
                                     "trigger": trigger}
        if outcome == "promoted" and auto:
            st["auto_promotions"].append(now)
        why = reason or {
            "promoted": "gate PASS, promoted by part_b.py, smoke test OK",
            "ready": "gate PASS; waiting for your approval",
            "gate_fail": "gate FAIL; models/ unchanged",
            "shadow_fail": "gate PASS but the shadow check FAILED on current traffic; models/ unchanged",
            "rolled_back": "promoted, smoke test failed, part_b.py rolled back",
            "promote_busy": "gate PASS; detection was running, promote will be retried",
            "data_missing": "training data missing (exit 4); inputs not marked trained",
        }.get(outcome, f"training command exited {rc}")
        self.log("run_finished", decision=outcome, trigger=trigger, run=run, exit=rc, reason=why,
                 inputs_marked_trained=trained, **extra)
        self.check_models(h0, outcome, run, trigger)
        self.save_state()
        return outcome

    # ── promote retry (only after an auto-promote run found detection busy) ───
    def retry_promote(self, now):
        pp = self.state.get("pending_promote")
        if pp and not self.auto_promote:                      # restarted without auto-promote: hand it over
            self.state["pending_promote"] = None
            self.state["last_ready"] = self.ready_info(pp["run"], self.part_b_line(pp["run"]))
            self.log("promote_retry", decision="ready_to_promote_manually", trigger=pp.get("trigger"),
                     run=pp["run"], reason="auto-promote is off now; promote by hand",
                     promote_command=self.state["last_ready"]["command"])
            self.save_state()
            return None
        if not pp or now < pp.get("next_at", 0):
            return None
        if self.locked_reason():
            return None                                       # try again next poll
        run = pp["run"]
        logf = self.train_log(run + "_promote")
        h0 = hash_models_all(self.guard_dirs)
        rc = self.run_logged(self.part_b_cmd(run, pp["seeds"]), python_env(self.cfg), logf)
        pp["attempts"] = pp.get("attempts", 0) + 1
        outcome, pb = self.outcome(rc, run, logf, True)
        max_n = int(self.cfg["promote_retry"]["max_attempts"])
        if outcome == "promote_busy" and pp["attempts"] < max_n:
            pp["next_at"] = now + float(self.cfg["promote_retry"]["interval_s"])
            self.log("promote_retry", decision="busy, will retry", trigger=pp.get("trigger"), run=run, exit=rc,
                     attempt=pp["attempts"], max_attempts=max_n)
        elif outcome == "promote_busy":
            self.state["pending_promote"] = None
            self.state["last_ready"] = self.ready_info(run, pb)
            self.log("promote_retry", decision="ready_to_promote_manually", trigger=pp.get("trigger"), run=run,
                     exit=rc, attempt=pp["attempts"], promote_command=self.state["last_ready"]["command"],
                     reason=f"detection stayed busy for {max_n} attempts")
        else:
            self.state["pending_promote"] = None
            if outcome == "promoted":
                self.state["auto_promotions"].append(now)
            if outcome == "ready":
                self.state["last_ready"] = self.ready_info(run, pb)
            self.log("promote_retry", decision=outcome, trigger=pp.get("trigger"), run=run, exit=rc,
                     attempt=pp["attempts"])
        self.check_models(h0, outcome, run, pp.get("trigger"))
        self.save_state()
        return outcome

    # ── one poll ─────────────────────────────────────────────────────────────
    def poll(self):
        """Evaluate the triggers once; start at most one run. Returns the run outcome, a skip reason or None."""
        if self.state is None:
            self.startup()
        st = self.state
        now = self.now()
        retried = self.retry_promote(now)
        if retried:
            return f"promote_retry:{retried}"
        tc = self.cfg["triggers"]
        en = {k: bool(tc[k].get("enabled", True)) for k in ("captures", "verdicts", "drift")}
        before = json.dumps(st, sort_keys=True)

        if en["drift"]:
            st["drift"], _ = T.update_drift(st["drift"], soc_config.rpath(tc["drift"]["report"]))
        caps = []
        if en["captures"]:
            caps, _ = T.pending_captures(soc_config.rpath(tc["captures"]["dir"]), tc["captures"]["pattern"],
                                         st["captures"]["trained"], float(tc["captures"]["settle_seconds"]),
                                         now, bool(tc["captures"].get("require_sha256sums", True)))
        verds = []
        if en["verdicts"]:
            verds = T.settled_verdicts(T.load_store(soc_config.rpath(tc["verdicts"]["store"])),
                                       st["verdicts"].get("trained_until"),
                                       float(tc["verdicts"]["verdict_settle_minutes"]), now)
        n = int(tc["drift"]["consecutive_reports"])
        due_drift = T.drift_due(st["drift"], n, bool(tc["drift"].get("edge_triggered", True)))
        trigger, note = T.choose(caps, verds, due_drift, int(tc["verdicts"]["min_new_verdicts"]),
                                 bool(tc["drift"].get("require_new_data", True)), en)
        if note == "drift_without_new_data":
            st["drift"]["armed"] = False
            self.log("skipped", decision="skipped", trigger="drift", reason="drift_without_new_data",
                     drift_consecutive=st["drift"]["consecutive"])
        if trigger is None:
            if json.dumps(st, sort_keys=True) != before:
                self.save_state()
            return note
        st["last_trigger_seen"] = {"trigger": trigger, "time": T.iso(now), "captures": len(caps),
                                   "verdicts": len(verds), "drift_consecutive": st["drift"]["consecutive"]}

        if st.get("pending_promote"):
            self.log_once(f"pending:{trigger}:{st['pending_promote']['run']}", event="skipped",
                          decision="skipped", trigger=trigger, reason="promote_pending")
            self.save_state()
            return "promote_pending"
        cu = st.get("cooldown_until")
        if cu and now < cu:
            self.log_once(f"cooldown:{trigger}:{cu}", event="skipped", decision="skipped", trigger=trigger,
                          reason="cooldown", cooldown_until=T.iso(cu))
            self.save_state()
            return "cooldown"
        day = [t for t in st.get("run_starts", []) if now - t < 86400]
        if len(day) >= int(self.cfg["max_runs_per_day"]):
            self.log_once(f"action_limit:{trigger}:{min(day)}", event="skipped", decision="skipped",
                          trigger=trigger, reason="action_limit",
                          detail=f"{len(day)} runs in the last 24 h (max_runs_per_day)")
            self.save_state()
            return "action_limit"
        why = self.locked_reason()
        if why:
            self.log_once(f"locked:{trigger}:{why}", event="skipped", decision="skipped", trigger=trigger,
                          reason="locked", detail=why)
            self.save_state()
            return "locked"
        st["logged"] = {k: v for k, v in st.get("logged", {}).items() if not k.startswith("locked:")}
        return self.run_training(trigger, caps, verds, st["drift"]["consecutive"])

    def run_forever(self):
        def on_term(signum, frame):
            self.stop = True
        signal.signal(signal.SIGTERM, on_term)
        signal.signal(signal.SIGINT, on_term)
        self.say(f"python {self.cfg['_python']} ({self.cfg['_python_source']}); config "
                 f"{self.cfg.get('_config_file')}; auto_promote={self.auto_promote}")
        self.beat()
        self.startup()
        interval = float(self.cfg["poll_interval_s"])
        while not self.stop:
            self.beat()
            try:
                self.poll()
            except NotAllowed:
                raise
            except Exception as e:  # keep the service alive; the supervisor restarts it only if it dies
                self.say(f"poll error: {type(e).__name__}: {e}")
            end = time.time() + interval
            last = time.time()
            while not self.stop and time.time() < end:
                time.sleep(min(1.0, max(0.0, end - time.time())))
                if time.time() - last >= 15:
                    self.beat()
                    last = time.time()
        self.say("stopped")
        return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--once", action="store_true", help="evaluate the triggers once, then exit")
    ap.add_argument("--auto-promote", action="store_true", help="promote on gate PASS (default: stop at ready)")
    ap.add_argument("--config", help="config file (default $SOC_CONFIG or config/soc.yaml)")
    a = ap.parse_args(argv)
    cfg = soc_config.load(a.config)
    lr = Learner(cfg, auto_promote=a.auto_promote)
    if a.once:
        lr.beat()
        result = lr.poll()
        print(result or "idle")
        return 0
    return lr.run_forever()


if __name__ == "__main__":
    sys.exit(main())
