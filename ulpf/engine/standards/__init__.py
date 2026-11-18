"""
Industry schemas for the unified event: OCSF 1.3.0 (``ocsf``), Google Security
Operations UDM (``udm``) and Microsoft Sentinel ASIM (``asim``). Each module has
``to_<std>``, ``from_<std>`` and ``validate``; ``facets`` classifies events and
collects the vendor details the three share. The bundled ``*.json`` files are
the schemas' published definitions (``scripts/build_ocsf_schema.py``,
``scripts/build_standards_catalog.py``).
"""
