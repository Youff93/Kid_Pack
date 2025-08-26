
import io, re, json, zipfile, csv
from xml.etree import ElementTree as ET
import streamlit as st
import pandas as pd

# ---- Helpers ----
DECL_RE = re.compile(r'^\s*(<\?xml[^>]*\?>)\s*', re.I)

def normalize(s: str) -> str:
    import re as _re
    return _re.sub(r"\s+", " ", (s or "").lower()).strip()

def parse_xml_text(text: str) -> ET.ElementTree:
    return ET.ElementTree(ET.fromstring(text))

def list_events(tree: ET.ElementTree):
    root = tree.getroot()
    for ev in root.iter("Event"):
        comp = None
        for c in root.iter("Composition"):
            comp = c; break
        if comp is None:
            continue
        ann_el = comp.find("AnnotationText")
        dur_el = comp.find("IntrinsicDuration")
        rate_el = comp.find("EditRate")
        ann = ann_el.text if ann_el is not None else ""
        dur = dur_el.text if dur_el is not None else ""
        rate = rate_el.text if rate_el is not None else ""
        yield ev, ann, dur, rate

def remove_blacklisted_events_with_log(tree: ET.ElementTree, blacklist_norm_keys:set):
    root = tree.getroot()
    removed = 0
    logs = []
    def should_remove(ev):
        comp = ev.find(".//Composition")
        ann_el = comp.find("AnnotationText") if comp is not None else None
        ann = ann_el.text if ann_el is not None else ""
        key = normalize(ann)
        return key in blacklist_norm_keys, ann
    for evlist in root.iter("EventList"):
        to_remove = []
        for ev in list(evlist.findall("Event")):
            ok, ann = should_remove(ev)
            if ok:
                to_remove.append((ev, ann))
        for ev, ann in to_remove:
            evlist.remove(ev); removed += 1
            logs.append({"Annotation": ann or "", "Reason": "blacklisted"})
    if removed == 0:
        for parent in root.iter():
            evs = list(parent.findall("Event"))
            any_removed = False
            for ev in evs:
                ok, ann = should_remove(ev)
                if ok:
                    parent.remove(ev); removed += 1; any_removed = True
                    logs.append({"Annotation": ann or "", "Reason": "blacklisted"})
            if any_removed:
                break
    return removed, logs

def compact_xml(xml: str) -> str:
    import re as _re
    return _re.sub(r">\s+<", "><", xml.strip())

SHOWTITLE_RE = re.compile(r'(<ShowTitleText[^>]*>)([^<]*)(</ShowTitleText>)', re.I)
ANNOT_RE     = re.compile(r'(<AnnotationText[^>]*>)([^<]*)(</AnnotationText>)', re.I)
ID_ELEM_RE   = re.compile(r'(<Id[^>]*>)([^<]*)(</Id>)', re.I)
ID_ATTR_RE   = re.compile(r'(\b[A-Za-z0-9_:+\-\.\{\}]*?id\s*=\s*)(["\'])([^"\']*)(\2)', re.I)

def _append_kid_once(txt: str) -> str:
    return txt if txt.endswith("KID") else (txt + "KID")

def _replace_last3_with_kid(val: str) -> str:
    if val.endswith("KID"): return val
    return (val[:-3] + "KID") if len(val) > 3 else (val + "KID")

def patch_top5_lines(xml: str) -> str:
    lines = xml.splitlines(keepends=True)
    n = min(5, len(lines))
    head = ''.join(lines[:n]); tail = ''.join(lines[n:])
    def show_repl(m): return f"{m.group(1)}{_append_kid_once(m.group(2))}{m.group(3)}"
    head, _ = SHOWTITLE_RE.subn(show_repl, head, count=1)
    def annot_repl(m): return f"{m.group(1)}{_append_kid_once(m.group(2))}{m.group(3)}"
    head, _ = ANNOT_RE.subn(annot_repl, head, count=1)
    def id_elem_repl(m): return f"{m.group(1)}{_replace_last3_with_kid(m.group(2))}{m.group(3)}"
    head, changed_elem = ID_ELEM_RE.subn(id_elem_repl, head, count=1)
    if changed_elem == 0:
        def id_attr_repl(m):
            prefix, quote, val, _q2 = m.groups()
            return f"{prefix}{quote}{_replace_last3_with_kid(val)}{quote}"
        head, _ = ID_ATTR_RE.subn(id_attr_repl, head, count=1)
    return head + tail

# ---- App ----
st.set_page_config(page_title="UGC - KID PACK", page_icon="🧩", layout="wide")
st.title("UGC - KID PACK")

# Single source of truth
st.session_state.setdefault("bl_text", "")

col1, col2 = st.columns([2,1])

with col1:
    uploads = st.file_uploader("Charge plusieurs XML", type=["xml"], accept_multiple_files=True)
    st.checkbox("Conserver déclaration XML d’origine (forcé)", value=True, disabled=True)
    st.checkbox("Sortie compacte (minifiée) (forcé)", value=True, disabled=True)
    suffix = st.text_input("Suffixe export (nom de fichier seulement)", value="_KIDSAFE")

with col2:
    st.markdown("### Blacklist")
    bl_file = st.file_uploader("Importer une blacklist (.txt)", type=["txt"], accept_multiple_files=False, key="bl_file")
    if bl_file is not None:
        try:
            txt = bl_file.read().decode("utf-8", errors="replace")
            lines = [l.strip() for l in txt.splitlines() if l.strip()]
            st.session_state["bl_text"] = "\n".join(lines)
            st.success(f"Blacklist importée : {len(lines)} ligne(s).")
        except Exception as e:
            st.error(f"Erreur import blacklist : {e}")
    st.text_area("Contenu de la blacklist (1 par ligne)", value=st.session_state.get("bl_text",""), height=200, key="bl_text")

# Build aggregation
agg = {}
files_parsed = []
if uploads:
    for uf in uploads:
        try:
            raw = uf.read().decode("utf-8", errors="replace")
            decl_m = DECL_RE.match(raw or "")
            decl_str = decl_m.group(1) if decl_m else None
            tree = parse_xml_text(raw)
            files_parsed.append({"name": uf.name, "text": raw, "decl": decl_str, "tree": tree})
            for _, ann, dur, rate in list_events(tree):
                key = normalize(ann)
                if not key: continue
                if key not in agg:
                    agg[key] = {"Annotation": ann, "Occurrences": 0, "EditRate": rate or "—", "Durée": dur or "—"}
                agg[key]["Occurrences"] += 1
        except Exception as e:
            st.error(f"Erreur XML ({uf.name}) : {e}")

if agg:
    st.subheader("Aperçu des annotations — sélection multiple")
    rows = [{"✔": False, **v} for v in sorted(agg.values(), key=lambda x: (-x["Occurrences"], x["Annotation"]))]
    df = pd.DataFrame(rows)

    use_table_selector = True
    selected_ann = []

    # Robust selector with graceful fallback
    try:
        edited = st.data_editor(
            df,
            use_container_width=True,
            hide_index=True,
            key="agg_editor",
            column_config={
                "✔": st.column_config.CheckboxColumn("✔", help="Cocher pour ajouter à la blacklist"),
                "Annotation": st.column_config.TextColumn("Annotation"),
                "Occurrences": st.column_config.NumberColumn("Occurrences"),
                "EditRate": st.column_config.TextColumn("EditRate"),
                "Durée": st.column_config.TextColumn("Durée"),
            }
        )
        selected_ann = [row["Annotation"] for _, row in edited.iterrows() if row.get("✔")]
    except Exception as e:
        use_table_selector = False
        st.warning("Tableau éditable indisponible dans cet environnement. Passage en mode compatibilité (cases à cocher).")
        selected_ann = []
        for i, row in df.iterrows():
            if st.checkbox(f"{row['Annotation']}  ({row['Occurrences']})", key=f"ck_{i}"):
                selected_ann.append(row["Annotation"])

    if st.button("Ajouter la sélection à la blacklist"):
        current = [l for l in st.session_state.get("bl_text","").splitlines() if l.strip()]
        seen = set(); dedup = []
        for item in current + selected_ann:
            key = normalize(item)
            if key and key not in seen:
                seen.add(key); dedup.append(item)
        st.session_state["bl_text"] = "\n".join(dedup)
        st.success(f"{len(selected_ann)} élément(s) ajoutés à la blacklist.")

# Export
if st.button("Appliquer blacklist & Exporter en ZIP", type="primary"):
    if not files_parsed:
        st.warning("Charge au moins un XML.")
    else:
        bl_keys = {normalize(x) for x in st.session_state.get("bl_text","").splitlines() if normalize(x)}
        mem_zip = io.BytesIO()
        exported, removed_total = 0, 0
        log_rows = []

        with zipfile.ZipFile(mem_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for rec in files_parsed:
                tree = rec["tree"]
                removed, logs = remove_blacklisted_events_with_log(tree, bl_keys)
                removed_total += removed

                xml_bytes = ET.tostring(tree.getroot(), encoding="utf-8", xml_declaration=False, short_empty_elements=False)
                xml = xml_bytes.decode("utf-8")

                if rec["decl"]:
                    xml = rec["decl"] + "\n" + xml.lstrip()
                else:
                    import re as _re
                    xml = _re.sub(r"^\s*<\?xml[^>]*>\s*", "", xml).lstrip()

                xml = compact_xml(xml)
                xml = patch_top5_lines(xml)

                base = rec["name"].rsplit(".", 1)[0]
                out_name = f"{base}{suffix}.xml"
                zf.writestr(out_name, xml)
                exported += 1

                for item in logs:
                    log_rows.append({"Fichier": rec["name"], "Annotation retirée": item.get("Annotation",""), "Raison": item.get("Reason","blacklisted")})

        mem_zip.seek(0)
        st.success(f"Export OK : {exported} fichier(s) – Éléments retirés : {removed_total}")
        st.download_button("Télécharger le ZIP", mem_zip, file_name="export_spl_batch.zip", mime="application/zip")

        st.subheader("Logs des éléments retirés")
        if log_rows:
            df_log = pd.DataFrame(log_rows)
            st.dataframe(df_log, use_container_width=True)
            csv_buf = io.StringIO()
            df_log.to_csv(csv_buf, index=False)
            st.download_button("Télécharger les logs (CSV)", csv_buf.getvalue().encode("utf-8"), file_name="logs_retraits.csv", mime="text/csv")
        else:
            st.info("Aucun élément retiré.")
