"""Streamlit admin console.  Run:  streamlit run streamlit_app.py"""
import pandas as pd
from pathlib import Path

import streamlit as st

from core import data, jobs, registry
from core import settings as S

st.set_page_config(page_title="Training console", layout="wide")

if st.sidebar.text_input("Admin token", type="password") != S.ADMIN_TOKEN:
    st.sidebar.info("Enter the admin token to continue.")
    st.stop()

page = st.sidebar.radio("Step", ["1. Data", "2. Train", "3. Runs", "4. Models"])
pct = lambda v: "-" if v is None else f"{v * 100:.2f}%"
LBL = {"f1": "F1", "precision": "Precision", "recall": "Recall", "pr_auc": "PR-AUC", "accuracy": "Accuracy",
       "fpr": "False positive rate", "false_alarms": "False alarms"}
fmt = lambda k, v: "-" if v is None else (str(v) if k == "false_alarms" else pct(v))
alarm = lambda m: pct(m["fpr"]) if m.get("fpr") is not None else (f"{m['false_alarms']} false alarms" if m.get("false_alarms") is not None else "-")


def safe(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except Exception as e:
        st.error(str(e))


if page == "1. Data":
    st.header("Data")
    up = st.file_uploader("Upload a dataset file", type=[e.strip(".") for e in sorted(S.UPLOAD_EXTS)])
    if up and st.button("Save and check"):
        (S.DATASETS / Path(up.name).name).write_bytes(up.getvalue())
        st.success(f"Saved {up.name}")
    names = [d["name"] for d in data.list_datasets()]
    if names:
        pick = st.selectbox("Check a dataset", names)
        r = safe(data.validate_csv, pick)
        if r:
            c1, c2, c3 = st.columns(3)
            c1.metric("Rows", r["rows"] if r["rows"] is not None else "?"); c2.metric("Features", len(r["numeric_features"])); c3.metric("Empty cells", f"{r['missing_pct']}%")
            if r["class_counts"]:
                st.bar_chart(pd.Series(r["class_counts"], name="rows"))
            for e in r["errors"]: st.error(e)
            for w in r["warnings"]: st.warning(w)
            if r["ok"]: st.success("Ready to train.")
            st.dataframe(pd.DataFrame(r["preview"]))
    else:
        st.info("No datasets yet. Upload a CSV above.")

elif page == "2. Train":
    st.header("Train")
    st.caption("Training creates a candidate model. It never changes production.")
    names = [d["name"] for d in data.list_datasets()]
    if not names:
        st.info("Add a dataset in step 1 first.")
        st.stop()
    labels = {d["name"]: d.get("label") or d["name"] for d in data.list_datasets()}
    ds = st.selectbox("Dataset", names, format_func=labels.get)
    path = st.selectbox("Models to train", ["both", "A", "B"], format_func={"both": "Both paths (A and B)", "A": "Path A: Random Forest + Transformer", "B": "Path B: Trafficformer"}.get)
    c = st.columns(4)
    if S.MODE == "capstone":
        params = {"seed": int(c[0].number_input("Random seed", 0, 99999, 42)),
                  "n_days": int(c[1].number_input("Window size, Path B (queries)", 1, 500, 20)),
                  "path_b_model": c[2].selectbox("Path B algorithm", ["trafficformer", "iforest"]),
                  "retrain": c[3].selectbox("Data to train on", ["all", "new_only"], format_func={"all": "All files in the dataset", "new_only": "Only files not trained before"}.get),
                  "pcap_label": st.selectbox("Label for .pcap files", ["", "0", "1"], format_func={"": "Unlabeled", "0": "Benign", "1": "Attack"}.get),
                  "new_split": st.checkbox("Make a fresh time-ordered split (changes the test set, so results are not comparable with earlier runs)"),
                  "allow_heuristic_labels": st.checkbox("Allow heuristic labels (experimental)")}
    else:
        params = {"n_estimators": int(c[0].number_input("Trees (Path A)", 10, 2000, 200)),
                  "epochs": int(c[1].number_input("Epochs (Path B)", 1, 500, 10)),
                  "test_size": float(c[2].number_input("Test split", 0.05, 0.5, 0.2, 0.05)),
                  "seed": int(c[3].number_input("Random seed", 0, 99999, 42))}
    if st.button("Start training", type="primary"):
        check = safe(data.validate_csv, ds)
        if check and not check["ok"]:
            st.error("; ".join(check["errors"]))
        elif check:
            j = safe(jobs.start_job, ds, path, params)
            if j:
                st.session_state["run"] = j["run_id"]
                st.success(f"Started {j['run_id']}. Open step 3 to watch it.")

elif page == "3. Runs":
    st.header("Runs")

    @st.fragment(run_every=2)
    def live():
        js = jobs.list_jobs()
        if not js:
            st.info("No runs yet. Start one in step 2.")
            return
        ids = [j["run_id"] for j in js]
        run = st.selectbox("Run", ids, index=ids.index(st.session_state.get("run", ids[0])) if st.session_state.get("run") in ids else 0)
        j = jobs.get_job(run)
        st.write(f"**{run}**: {j['status']}")
        m = jobs.get_metrics(run)
        if m:
            ks = [k for k in LBL if m.get(k) is not None]
            for col, k in zip(st.columns(max(len(ks), 1)), ks):
                col.metric(LBL[k], fmt(k, m[k]))
            if m.get("note"):
                st.warning(m["note"])
            if m.get("loss_curve"):
                st.line_chart(m["loss_curve"])
        st.code(jobs.tail_log(run) or "Waiting for output...", language="text")
        if j["status"] == "running" and st.button("Cancel run"):
            safe(jobs.cancel_job, run)

    live()

else:
    st.header("Models")
    ms = registry.list_models()
    if not ms:
        st.info("Models appear here after a run finishes.")
    else:
        st.dataframe(pd.DataFrame([{"version": m["version"], "dataset": m["dataset"], "f1": pct(m["metrics"].get("f1")),
                                    "false alarms": alarm(m["metrics"]),
                                    "status": "production" if m["is_production"] else "candidate"} for m in reversed(ms)]), hide_index=True)
        cands = [m["version"] for m in ms if not m["is_production"]]
        if cands:
            v = st.selectbox("Compare candidate with production", cands)
            cmp = safe(registry.compare, v)
            if cmp:
                st.dataframe(pd.DataFrame(cmp["rows"]), hide_index=True)
                for w in cmp["warnings"]: st.warning(w)
                override = st.checkbox("Promote even though the checks above flagged a problem") if cmp["warnings"] else False
                if st.button(f"Promote {v} to production", type="primary"):
                    if safe(registry.promote, v, override):
                        st.success(f"{v} is now in production.")
                        st.rerun()
    if st.button("Roll back to previous version"):
        if safe(registry.rollback):
            st.rerun()
