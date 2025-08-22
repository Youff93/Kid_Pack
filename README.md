
# UGC – KID PACKS (Streamlit)

## Installation
```bash
pip install -r requirements.txt
```

## Lancement
```bash
streamlit run app.py
```

## Fonctionnalités
- Upload multi-XML
- Agrégation et aperçu des `AnnotationText`
- Blacklist éditable (et normalisable via JSON)
- Options : conserver déclaration XML, sortie compacte ou pretty-print
- Patch KID ciblé sur les 5 premières lignes (ShowTitleText, AnnotationText, Id)
- Export d'un ZIP avec suffixe configurable dans le nom de fichier

## Notes
- Tout est local, aucun envoi externe.
- Testé avec Python 3.9+.
# Kid_Pack
