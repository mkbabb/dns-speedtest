CREATE
OR REPLACE VIEW pcap_speedtest_data AS WITH ranked_packets AS (
    SELECT
        id,
        transaction_uuid,
        TIMESTAMP,
        flags,
        src_ip,
        SIZE,
        ROW_NUMBER() OVER (
            PARTITION BY transaction_uuid
            ORDER BY
                TIMESTAMP
        ) AS rn,
        LAG(id) OVER (
            ORDER BY
                id
        ) AS prev_id
    FROM
        packet_capture_results
),
transaction_stats AS (
    SELECT
        rp.transaction_uuid,
        MIN(rp.id) AS min_id,
        MIN(
            CASE
                WHEN rp.flags = 'PA'
                OR rp.flags = 'SPA'
                OR rp.flags = 'A'
                AND rp.src_ip NOT LIKE '10.%' THEN rp.timestamp
            END
        ) AS first_pa_timestamp,
        MAX(
            CASE
                WHEN (
                    rp.flags = 'FA'
                    OR rp.flags = 'FPA'
                    OR rp.flags = 'A'
                )
                AND rp.src_ip NOT LIKE '10.%' THEN rp.timestamp
            END
        ) AS last_fa_timestamp,
        MIN(
            CASE
                WHEN rp.flags = 'A'
                AND rp.src_ip NOT LIKE '10.%' THEN (
                    SELECT
                        MAX(sa.timestamp)
                    FROM
                        packet_capture_results sa
                    WHERE
                        sa.flags = 'SA'
                        AND sa.src_ip LIKE '10.%'
                        AND sa.id <= rp.prev_id
                )
            END
        ) AS first_sa_timestamp,
        MIN(
            CASE
                WHEN rp.flags = 'A'
                AND rp.src_ip NOT LIKE '10.%' THEN rp.timestamp
            END
        ) AS first_a_timestamp,
        SUM(
            CASE
                WHEN rp.src_ip LIKE '10.%' THEN rp.size
                ELSE 0
            END
        ) AS total_bytes,
        COUNT(
            CASE
                WHEN rp.src_ip LIKE '10.%' THEN 1
            END
        ) AS packets_sent
    FROM
        ranked_packets rp
    WHERE
        rp.transaction_uuid IS NOT NULL
    GROUP BY
        rp.transaction_uuid
),
calculated_stats AS (
    SELECT
        *,
        NULLIF(
            (last_fa_timestamp - first_pa_timestamp) / 1e9,
            0
        ) AS total_duration_seconds,
        CASE
            WHEN first_sa_timestamp IS NOT NULL
            AND first_a_timestamp IS NOT NULL THEN NULLIF(
                (first_a_timestamp - first_sa_timestamp) / 1e9,
                0
            )
            ELSE NULL
        END AS rtt_seconds
    FROM
        transaction_stats
),
final_stats AS (
    SELECT
        *,
        CASE
            WHEN rtt_seconds IS NOT NULL THEN NULLIF(total_duration_seconds - 2 * rtt_seconds, 0)
            ELSE total_duration_seconds
        END AS adjusted_duration_seconds,
        total_bytes / 1e6 AS total_mb
    FROM
        calculated_stats
)
SELECT
    min_id AS original_id,
    transaction_uuid,
    packets_sent,
    total_bytes,
    total_mb,
    rtt_seconds,
    total_duration_seconds,
    adjusted_duration_seconds,
    CASE
        WHEN adjusted_duration_seconds IS NOT NULL
        AND adjusted_duration_seconds > 0 THEN ROUND(total_mb / adjusted_duration_seconds, 2)
        ELSE NULL
    END AS mb_per_second
FROM
    final_stats
WHERE
    first_pa_timestamp IS NOT NULL
    AND last_fa_timestamp IS NOT NULL
ORDER BY
    original_id ASC