-- Persisted exit-node selection (forwarding). NULL = no exit node selected.
ALTER TABLE nodes ADD COLUMN exit_node_id TEXT;
