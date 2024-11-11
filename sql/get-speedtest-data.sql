WITH ranked_results AS (
    SELECT
        *,
        ROW_NUMBER() OVER (
            PARTITION BY dns_url_id
            ORDER BY
                speedtest_dl_speed DESC
        ) AS rn
    FROM
        combined_dns_data
    WHERE
        dns_url_uid = :uid
        AND packet_capture_transaction_uuid IS NOT NULL
        AND speedtest_dl_speed IS NOT NULL
)
SELECT
    *
FROM
    ranked_results
WHERE
    rn = 1;