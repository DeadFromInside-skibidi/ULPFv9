"""
ULPF lakehouse: hot Arrow tier on local NVMe (memory-mapped ring), cold Delta Lake tier on local
disk, S3 / MinIO / Ceph or Azure Blob (client-side AES-256-GCM), a compaction daemon, and
federated DuckDB / Arrow Flight queries with partition, statistics and bloom-filter pruning.

Modules: ``store`` (object stores), ``crypto`` (keys, MAC chain), ``schema``, ``hot`` (ring),
``delta`` (transaction log), ``files`` (data files, blooms), ``service`` (daemons),
``query`` (federation), ``flight`` (Arrow Flight). Output type: ``lakehouse``.
"""
