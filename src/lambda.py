import json
import os
from typing import Any
import boto3
import sqlalchemy
from sqlalchemy.sql import text
from datetime import date, datetime
from decimal import Decimal

client = boto3.client("secretsmanager")

# Database name as a variable
DNS_SPEEDTEST_DB = "dns-speedtest"


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (date, datetime)):
            return obj.isoformat()
        if isinstance(obj, Decimal):
            return float(obj)
        if isinstance(obj, bytes):
            return obj.hex()  # Convert binary data to hex string for JSON serialization
        return super().default(obj)


def open_mysql_conn(
    username: str, password: str, host: str, port: str, database: str, **kwargs: Any
) -> sqlalchemy.engine.Engine:
    engine_str = f"mysql+pymysql://{username}:{password}@{host}:{port}/{database}"
    engine = sqlalchemy.create_engine(engine_str)
    return engine


def get_latest_speedtest_data(
    uid: str, engine: sqlalchemy.engine.Engine
) -> dict | None:
    query = text(
        """
WITH ranked_results AS (
  SELECT 
    *,
    ROW_NUMBER() OVER (PARTITION BY dns_url_id ORDER BY speedtest_dl_speed DESC) as rn
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
    """
    )

    with engine.connect() as conn:
        result = conn.execute(query, {"uid": uid}).fetchone()

        return result._asdict() if result else None


def get_latest_pcap_data(
    uid: str, engine: sqlalchemy.engine.Engine
) -> list[dict] | None:
    query = text(
        """
WITH latest_transaction AS (
    SELECT 
        r.transaction_uuid
    FROM 
        requests r
        JOIN dns_urls d ON d.id = r.dns_url_id
    WHERE 
        d.uid = :uid
    ORDER BY 
        r.start_time DESC
    LIMIT 1
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
    latest_transaction lt
    JOIN dns_urls d ON d.uid = :uid
    JOIN packet_capture_results pcr ON pcr.transaction_uuid = lt.transaction_uuid
    JOIN packet_capture_raw_data pcrd ON pcrd.packet_capture_result_id = pcr.id
ORDER BY
    pcr.capture_time ASC;
    """
    )

    with engine.connect() as conn:
        result = conn.execute(query, {"uid": uid}).fetchall()
        if result is None:
            return None

        results = [row._asdict() for row in result]
        # extract out only the packet_json field
        return [json.loads(row['packet_json']) for row in results]


def get_data_for_resource(
    resource: str, uid: str, engine: sqlalchemy.engine.Engine
) -> dict | list[dict] | None:
    """
    Route the request to the appropriate data fetching function based on the path
    """
    resource_handlers = {
        "/dns-results/speedtest/{uid+}": get_latest_speedtest_data,
        "/dns-results/pcap/{uid+}": get_latest_pcap_data,
    }

    handler = resource_handlers.get(resource)

    if not handler:
        raise ValueError(f"Invalid resource: {resource}")

    return handler(uid=uid, engine=engine)


def lambda_handler(event: dict, context: dict):
    # CORS headers
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
        'Access-Control-Allow-Methods': 'GET,OPTIONS',
    }

    # Handle preflight OPTIONS request
    if event['httpMethod'] == 'OPTIONS':
        return {'statusCode': 200, 'headers': headers, 'body': ''}

    try:
        # Get path and UID from the event
        resource = event['resource']
        uid = event['pathParameters']['uid']

        # Get database secrets
        response = client.get_secret_value(SecretId=os.environ["SecretId"])
        secrets = json.loads(response.get("SecretString"))
        secrets['database'] = DNS_SPEEDTEST_DB

        # Open database connection
        engine = open_mysql_conn(**secrets)

        # Get the appropriate data based on the path
        result = get_data_for_resource(resource=resource, uid=uid, engine=engine)

        if result:
            return {
                'statusCode': 200,
                'body': json.dumps(result, cls=CustomJSONEncoder),
                'headers': {**headers, 'Content-Type': 'application/json'},
            }
        else:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': f'No data found for UID: {uid}'}),
                'headers': {**headers, 'Content-Type': 'application/json'},
            }

    except ValueError as e:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': str(e), "event": json.dumps(event)}),
            'headers': {**headers, 'Content-Type': 'application/json'},
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)}),
            'headers': {**headers, 'Content-Type': 'application/json'},
        }
