WITH request_ids AS (
    SELECT
        r.id,
        r.transaction_uuid
    FROM
        requests r
)
SELECT
    d.domain,
    pcr.timestamp,
    pcr.capture_time,
    pcr.src_ip,
    pcr.src_port,
    pcr.dst_ip,
    pcr.dst_port,
    pcr.protocol,
    pcr.flags,
    pcr.sequence_number,
    pcr.acknowledgment_number,
    pcrd.packet_binary,
    pcrd.packet_json
FROM
    request_ids ri
    JOIN dns_urls d ON d.uid = :uid
    JOIN packet_capture_results pcr ON pcr.transaction_uuid = ri.transaction_uuid
    JOIN packet_capture_raw_data pcrd ON pcrd.packet_capture_result_id = pcr.id
ORDER BY
    pcr.capture_time ASC;