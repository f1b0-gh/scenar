# Acknowledgements and provenance

Scenar builds reproducible synthetic security datasets. The components below
retain their own identities, authorship and notices.

Scenar-owned code is licensed under the [Apache License 2.0](LICENSE).
This declaration does not replace the component notices below.

## EvidenceForge

[EvidenceForge](https://github.com/Cisco-Talos/EvidenceForge) is the external
telemetry-generation engine. Its name and runtime remain separate from Scenar.
Evaluation helpers and pack resources were extracted from an
inspected EvidenceForge-based source snapshot. Their original paths and hashes
are retained in [the extraction inventory](docs/extraction-provenance.json).

The [retained MIT notice](src/scenar/EVIDENCEFORGE-LICENSE.txt) credits Cisco
Systems, Inc. and its affiliates. The notice is shipped inside the Python package.
[Backend provenance](docs/evidenceforge-sync.md) distinguishes the inspected
snapshot from a verified upstream release; identical version numbers do not
establish source equivalence.

## MITRE ATT&CK

The packaged Enterprise catalogue is derived from MITRE ATT&CK. Its version and
source identity are recorded in `src/scenar/resources/attack/pin.json`.
[MITRE's notice and terms](src/scenar/resources/attack/LICENSE.txt) accompany the
catalogue in source and binary distributions. ATT&CK mappings describe coverage;
they are not proof that all behaviors or telemetry sources are represented.

