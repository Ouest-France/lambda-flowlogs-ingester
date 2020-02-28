# lambda-flowlogs-ingester

A Golang AWS lambda to read flowlogs from S3 and index them in Elasticsearch.

## Env vars

* ES_HOST : AWS Elasticsearch service host
* ES_REGION : AWS Elasticsearch service region
* ES_INDEX: AWS Elasticsearch service index