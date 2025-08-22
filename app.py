
import io, re, json, zipfile
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

def remove_blacklisted_events(tree: ET.ElementTree, blacklist_norm_keys:set):
    root = tree.getroot()
    removed = 0
    for evlist in root.iter("EventList"):
        to_remove = []
        for ev in list(evlist.findall("Event")):
            comp = ev.find(".//Composition")
            ann_el = comp.find("AnnotationText") if comp is not None else None
            ann = ann_el.text if ann_el is not None else ""
            if normalize(ann) in blacklist_norm_keys:
                to_remove.append(ev)
        for ev in to_remove:
            evlist.remove(ev); removed += 1
    if removed == 0:
        for parent in root.iter():
            evs = list(parent.findall("Event"))
            any_removed = False
            for ev in evs:
                comp = ev.find(".//Composition")
                ann_el = comp.find("AnnotationText") if comp is not None else None
                ann = ann_el.text if ann_el is not None else ""
                if normalize(ann) in blacklist_norm_keys:
                    parent.remove(ev); removed += 1; any_removed = True
            if any_removed:
                break
    return removed

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
st.set_page_config(page_title="SPL Batch – Web", page_icon="🧩", layout="wide")
st.title("SPL Batch – Web")

col1, col2 = st.columns([2,1])

with col1:
    uploads = st.file_uploader("Charge plusieurs XML", type=["xml"], accept_multiple_files=True)
    keep_decl = st.checkbox("Conserver déclaration XML d’origine", value=True)
    compact   = st.checkbox("Sortie compacte (minifiée)", value=False)
    suffix    = st.text_input("Suffixe export (nom de fichier seulement)", value="_KIDSAFE")

with col2:
    st.markdown("### Blacklist")
    bl_text = st.text_area("Colle/édite ta blacklist (1 par ligne)", height=200)
    st.caption("Astuce : tu peux coller un JSON (liste) — il sera normalisé.")
    if st.button("Normaliser la blacklist"):
        try:
            parsed = json.loads(bl_text)
            bl_text = "\n".join(sorted({normalize(x) for x in parsed if normalize(x)}))
            st.experimental_rerun()
        except Exception:
            st.info("Pas du JSON ? Laisse tel quel, c’est ok.")

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

if agg:
    st.subheader("Aperçu des annotations agrégées")
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
        bl_keys = {normalize(x) for x in bl_text.splitlines() if normalize(x)}
        mem_zip = io.BytesIO()
        exported, removed_total = 0, 0
        with zipfile.ZipFile(mem_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for rec in files_parsed:
                tree = rec["tree"]
                removed = remove_blacklisted_events(tree, bl_keys)
                removed_total += removed

                xml_bytes = ET.tostring(tree.getroot(), encoding="utf-8", xml_declaration=False, short_empty_elements=False)
                xml = xml_bytes.decode("utf-8")

                if keep_decl:
                    if rec["decl"]:
                        xml = rec["decl"] + "\n" + xml.lstrip()
                    else:
                        import re as _re
                        xml = _re.sub(r"^\s*<\?xml[^>]*>\s*", "", xml).lstrip()
                else:
                    import re as _re
                    xml = _re.sub(r"^\s*<\?xml[^>]*>\s*", "", xml).lstrip()

                xml = compact_xml(xml) if compact else pretty_xml(xml)
                xml = patch_top5_lines(xml)

                base = rec["name"].rsplit(".", 1)[0]
                out_name = f"{base}{suffix}.xml"
                zf.writestr(out_name, xml)
                exported += 1

        mem_zip.seek(0)
        st.success(f"Export OK : {exported} fichier(s) – Éléments retirés : {removed_total}")
        st.download_button("Télécharger le ZIP", mem_zip, file_name="export_spl_batch.zip", mime="application/zip")
