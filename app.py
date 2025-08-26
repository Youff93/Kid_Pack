
import io, re, json, zipfile, csv
from xml.etree import ElementTree as ET
import streamlit as st

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
        for c in ev.iter("Composition"):
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
    logs = []  # list of dicts: {"Annotation":..., "Reason":"blacklisted"}
    def should_remove(ev):
        comp = ev.find(".//Composition")
        ann_el = comp.find("AnnotationText") if comp is not None else None
        ann = ann_el.text if ann_el is not None else ""
        key = normalize(ann)
        return key in blacklist_norm_keys, ann
    # Try within EventList first
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
        # fallback: remove directly under any parent
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

def pretty_xml(xml: str) -> str:
    import re as _re
    m = _re.match(r'^\s*(<\?xml[^>]*\?>)\s*', xml)
    decl = m.group(1) if m else '<?xml version="1.0" encoding="UTF-8"?>'
    body = xml[m.end():] if m else xml
    body = _re.sub(r'>\s+<', '><', body.strip())
    pad = 0; IND = '  '; out_lines = [decl]
    for token in _re.split(r'>\s*<', body):
        token = token.strip()
        if not token: continue
        if token.startswith('/'):
            pad = max(pad - 1, 0)
        line = (IND * pad) + '<' + token + '>'
        if (not token.startswith('/') and not token.endswith('/') 
            and not _re.search(r'<\w[^>]*>.*</\w', '<'+token+'>')):
            pad += 1
        out_lines.append(line)
    return '\n'.join(out_lines)

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

# ---- UI Streamlit ----
st.set_page_config(page_title="UGC - KID PACK", page_icon="🧩", layout="wide")
st.title("UGC - KID PACK")

# Session state for blacklist text and selections
if "bl_text" not in st.session_state:
    st.session_state.bl_text = ""
if "selected_from_agg" not in st.session_state:
    st.session_state.selected_from_agg = []

col1, col2 = st.columns([2,1])

with col1:
    uploads = st.file_uploader("Charge plusieurs XML", type=["xml"], accept_multiple_files=True)
    # Options forced ON and disabled
    keep_decl = st.checkbox("Conserver déclaration XML d’origine (forcé)", value=True, disabled=True)
    compact   = st.checkbox("Sortie compacte (minifiée) (forcé)", value=True, disabled=True)
    suffix    = st.text_input("Suffixe export (nom de fichier seulement)", value="_KIDSAFE")

with col2:
    st.markdown("### Blacklist")
    # Import .txt
    bl_file = st.file_uploader("Importer une blacklist (.txt)", type=["txt"], accept_multiple_files=False, key="bl_file")
    if bl_file is not None:
        try:
            txt = bl_file.read().decode("utf-8", errors="replace")
            # accept one per line
            lines = [l.strip() for l in txt.splitlines() if l.strip()]
            st.session_state.bl_text = "\n".join(lines)
            st.success(f"Blacklist importée : {len(lines)} ligne(s).")
        except Exception as e:
            st.error(f"Erreur import blacklist : {e}")

    bl_text_area = st.text_area("Colle/édite ta blacklist (1 par ligne)", value=st.session_state.bl_text, height=200, key="bl_text_area")
    # Sync back to session on edit
    st.session_state.bl_text = bl_text_area

    st.caption("Astuce : tu peux coller un JSON (liste) — il sera normalisé.")
    if st.button("Normaliser la blacklist"):
        try:
            parsed = json.loads(st.session_state.bl_text)
            st.session_state.bl_text = "\n".join(sorted({normalize(x) for x in parsed if normalize(x)}))
            st.experimental_rerun()
        except Exception:
            # Normalize current lines instead
            lines = [normalize(x) for x in st.session_state.bl_text.splitlines() if normalize(x)]
            st.session_state.bl_text = "\n".join(sorted(set(lines)))
            st.info("Normalisation effectuée sur les lignes (pas JSON).")
            st.experimental_rerun()

# Agrégation des annotations
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
                    agg[key] = {"ann": ann, "count": 0, "dur": dur, "rate": rate}
                agg[key]["count"] += 1
        except Exception as e:
            st.error(f"Erreur XML ({uf.name}) : {e}")

# Zone de sélection depuis l'agrégat
if agg:
    st.subheader("Aperçu des annotations agrégées")
    # Create a list for multiselect, show label as "Annotation (count)"
    options = [f"{v['ann']}  ({v['count']})" for v in sorted(agg.values(), key=lambda x: (-x["count"], x["ann"]))]
    label_to_ann = {f"{v['ann']}  ({v['count']})": v['ann'] for v in agg.values()}
    selected = st.multiselect("Sélectionne des médias à ajouter à la blacklist :", options, default=st.session_state.selected_from_agg)
    st.session_state.selected_from_agg = selected
    if st.button("Ajouter la sélection à la blacklist"):
        current = [l for l in st.session_state.bl_text.splitlines() if l.strip()]
        to_add = [label_to_ann[x] for x in selected]
        new_lines = current + to_add
        # de-dup preserving order
        seen = set(); dedup = []
        for item in new_lines:
            key = normalize(item)
            if key and key not in seen:
                seen.add(key); dedup.append(item)
        st.session_state.bl_text = "\n".join(dedup)
        st.success(f"{len(to_add)} élément(s) ajoutés à la blacklist.")
        st.experimental_rerun()
    # Show agg table
    st.dataframe(
        data=sorted(
            [{"Annotation": v["ann"], "Occurrences": v["count"], "EditRate": v["rate"] or "—", "Durée": v["dur"] or "—"}
             for v in agg.values()],
            key=lambda x: (-x["Occurrences"], x["Annotation"])
        ),
        use_container_width=True
    )

# Export
if st.button("Appliquer blacklist & Exporter en ZIP", type="primary"):
    if not files_parsed:
        st.warning("Charge au moins un XML.")
    else:
        bl_keys = {normalize(x) for x in st.session_state.bl_text.splitlines() if normalize(x)}
        mem_zip = io.BytesIO()
        exported, removed_total = 0, 0
        log_rows = []  # per file logs

        with zipfile.ZipFile(mem_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for rec in files_parsed:
                tree = rec["tree"]
                removed, logs = remove_blacklisted_events_with_log(tree, bl_keys)
                removed_total += removed

                xml_bytes = ET.tostring(tree.getroot(), encoding="utf-8", xml_declaration=False, short_empty_elements=False)
                xml = xml_bytes.decode("utf-8")

                # keep declaration ALWAYS
                if rec["decl"]:
                    xml = rec["decl"] + "\n" + xml.lstrip()
                else:
                    import re as _re
                    xml = _re.sub(r"^\s*<\?xml[^>]*>\s*", "", xml).lstrip()

                # compact ALWAYS
                xml = compact_xml(xml)

                # patch KID
                xml = patch_top5_lines(xml)

                base = rec["name"].rsplit(".", 1)[0]
                out_name = f"{base}{suffix}.xml"
                zf.writestr(out_name, xml)
                exported += 1

                # logs per file
                for item in logs:
                    log_rows.append({"Fichier": rec["name"], "Annotation retirée": item.get("Annotation",""), "Raison": item.get("Reason","blacklisted")})

        mem_zip.seek(0)
        st.success(f"Export OK : {exported} fichier(s) – Éléments retirés : {removed_total}")
        st.download_button("Télécharger le ZIP", mem_zip, file_name="export_spl_batch.zip", mime="application/zip")

        # Show logs
        st.subheader("Logs des éléments retirés")
        if log_rows:
            import pandas as pd
            df = pd.DataFrame(log_rows)
            st.dataframe(df, use_container_width=True)
            # CSV download
            csv_buf = io.StringIO()
            df.to_csv(csv_buf, index=False)
            st.download_button("Télécharger les logs (CSV)", csv_buf.getvalue().encode("utf-8"), file_name="logs_retraits.csv", mime="text/csv")
        else:
            st.info("Aucun élément retiré.")

# Zone d'édition finale de la blacklist (après ajouts)
st.markdown("### Blacklist courante")
st.text_area("Contenu de la blacklist (1 par ligne)", value=st.session_state.bl_text, height=150, key="bl_text_final")
st.session_state.bl_text = st.session_state.bl_text_final
