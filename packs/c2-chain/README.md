# C2 structural query

`scenar c2-query public-view.json.gz --start 2024-07-15T12:00:00Z` runs `find_chains`
against a public envelope. It requires unique process lineage, reconciled
endpoint/wire contacts and archive/upload evidence. Its assessment is
`linked_remote_workflow; intent_unresolved`, not a maliciousness verdict.

At least three reconciled contacts to one destination spanning ten seconds must
precede the child shell. Shorter bursts, two contacts, a single persistent
connection, destination rotation leaving fewer than three contacts per destination,
and unsupported transports can miss a workflow. The query performs a full scan;
it is not a bounded investigator.

The tests cover self-parent and ambiguous-lineage exclusions. Setting
`SCENAR_C2_ARCHIVE` also exercises the 12 archived public views, including linked
and unlinked controls, shared-parent jobs and withheld/late evidence. These are
exposed regression material; transformed views are not new independent captures.
See the [regression catalogue](../regressions.json) for the archive identity and
coverage limits.
