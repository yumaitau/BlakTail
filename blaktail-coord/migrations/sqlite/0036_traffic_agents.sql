-- Agent traffic records: the peer device a flow was with and which side
-- started it. Both are optional so earlier uploads stay valid.
ALTER TABLE flow_records ADD COLUMN peer_id TEXT;
ALTER TABLE flow_records ADD COLUMN direction TEXT;
