CREATE
OR REPLACE VIEW combined_dns_data AS
SELECT
    d.id AS dns_url_id,
    d.byte_len AS dns_url_byte_len,
    d.uid AS dns_url_uid,
    d.domain AS dns_url_domain,
    r.id AS request_id,
    r.protocol AS request_protocol,
    r.qtype AS request_qtype,
    r.start_time AS request_start_time,
    r.end_time AS request_end_time,
    r.ip AS request_ip,
    psd.mb_per_second AS speedtest_dl_speed,
    i.ip_address AS ip_info_address,
    i.location AS ip_info_location,
    i.org AS ip_info_org,
    i.postal AS ip_info_postal,
    i.city AS ip_info_city,
    i.region AS ip_info_region,
    i.country AS ip_info_country,
    p.transaction_uuid AS packet_capture_transaction_uuid,
    p.src_ip AS packet_capture_src_ip,
    p.src_port AS packet_capture_src_port,
    p.dst_ip AS packet_capture_dst_ip,
    p.dst_port AS packet_capture_dst_port,
    p.timestamp AS packet_capture_request_timestamp,
    p.timestamp AS packet_capture_response_timestamp,
    p.size AS packet_capture_request_size,
    p.size AS packet_capture_response_size,
    CAST(p.timestamp AS FLOAT) / 1e9 AS packet_capture_latency,
    CASE
        WHEN i.id IS NOT NULL THEN 'Yes'
        ELSE 'No'
    END AS has_ip_info,
    CASE
        WHEN p.transaction_uuid IS NOT NULL THEN 'Yes'
        ELSE 'No'
    END AS has_packet_capture_result
FROM
    dns_urls d
    LEFT JOIN requests r ON d.id = r.dns_url_id
    LEFT JOIN ipinfo i ON r.ipinfo_id = i.id
    LEFT JOIN packet_capture_results p ON r.transaction_uuid = p.transaction_uuid
    LEFT JOIN pcap_speedtest_data psd ON p.transaction_uuid = psd.transaction_uuid;