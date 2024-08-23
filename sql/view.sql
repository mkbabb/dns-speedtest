CREATE OR REPLACE VIEW combined_dns_data AS
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
    s.id AS speedtest_id,
    s.delta AS speedtest_delta,
    s.dl_speed AS speedtest_dl_speed,
    i.ip_address AS ip_info_address,
    i.location AS ip_info_location,
    i.org AS ip_info_org,
    i.postal AS ip_info_postal,
    i.city AS ip_info_city,
    i.region AS ip_info_region,
    i.country AS ip_info_country,
    CASE
        WHEN s.id IS NOT NULL THEN 'Yes'
        ELSE 'No'
    END AS has_speedtest_result,
    CASE
        WHEN i.id IS NOT NULL THEN 'Yes'
        ELSE 'No'
    END AS has_ip_info
FROM
    dns_urls d
LEFT JOIN
    requests r ON d.id = r.dns_url_id
LEFT JOIN
    speedtest_results s ON r.id = s.request_id
LEFT JOIN
    ipinfo i ON r.ipinfo_id = i.id;