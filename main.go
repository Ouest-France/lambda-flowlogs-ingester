package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/gocarina/gocsv"
	"github.com/olivere/elastic"
	esaws "github.com/olivere/elastic/aws/v4"
)

// LogEntry represents a flowlog entry
type LogEntry struct {
	Version          int    `csv:"version" json:"version"`
	AccountID        string `csv:"account-id" json:"account-id"`
	InterfaceID      string `csv:"interface-id" json:"interface-id"`
	SourceAddr       string `csv:"srcaddr" json:"srcaddr"`
	DestAddr         string `csv:"dstaddr" json:"dstaddr"`
	SourcePort       string `csv:"srcport" json:"srcport"`
	DestPort         string `csv:"dstport" json:"dstport"`
	Protocol         string `csv:"protocol" json:"protocol"`
	Packets          string `csv:"packets" json:"packets"`
	Bytes            string `csv:"bytes" json:"bytes"`
	Start            string `csv:"start" json:"start"`
	End              string `csv:"end" json:"end"`
	Action           string `csv:"action" json:"action"`
	LogStatus        string `csv:"log-status" json:"log-status"`
	InstanceID       string `csv:"instance-id" json:"instance-id"`
	PacketSourceAddr string `csv:"pkt-srcaddr" json:"pkt-srcaddr"`
	PacketDestAddr   string `csv:"pkt-dstaddr" json:"pkt-dstaddr"`
	SubnetID         string `csv:"subnet-id" json:"subnet-id"`
	Type             string `csv:"type" json:"type"`
	VPCID            string `csv:"vpc-id" json:"vpc-id"`
}

const mapping = `
{
    "settings" : {
		"number_of_shards" : 1,
		"number_of_replicas" : 0
    },
    "mappings" : {
        "properties" : {
            "start" : { "type" : "date", "format" : "epoch_second" },
            "end" : { "type" : "date", "format" : "epoch_second" },
            "srcaddr" : { "type" : "ip"},
            "dstaddr" : { "type" : "ip"},
            "pkt-srcaddr" : { "type" : "ip"},
            "pkt-dstaddr" : { "type" : "ip"},
			"bytes" : { "type" : "integer"},
			"packets" : { "type" : "integer"},
			"dstport" : { "type" : "integer"},
			"srcport" : { "type" : "integer"}
        }
    }
}`

func main() {
	lambda.Start(handler)
}

func handler(ctx context.Context, s3Event events.S3Event) {

	// Check env vars
	for _, envVar := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "ES_HOST", "ES_REGION", "ES_INDEX"} {
		if os.Getenv(envVar) == "" {
			fmt.Printf("env var %q must be defined", envVar)
			return
		}
	}

	// AWS ES signing client
	signingClient := esaws.NewV4SigningClient(credentials.NewStaticCredentials(
		os.Getenv("AWS_ACCESS_KEY_ID"),
		os.Getenv("AWS_SECRET_ACCESS_KEY"),
		os.Getenv("AWS_SESSION_TOKEN"),
	), os.Getenv("ES_REGION"))

	// Create ES client
	esclient, err := elastic.NewClient(elastic.SetURL(os.Getenv("ES_HOST")), elastic.SetSniff(false), elastic.SetHealthcheck(false), elastic.SetHttpClient(signingClient))
	if err != nil {
		fmt.Printf("error creating es client: %s\n", err)
		return
	}

	// For each S3 object in event
	for _, record := range s3Event.Records {

		// Build index name
		index := fmt.Sprintf("%s-%s-%s", os.Getenv("ES_INDEX"), record.S3.Bucket.Name, time.Now().Format("2006-01-02"))

		// Use the IndexExists service to check if a specified index exists.
		exists, err := esclient.IndexExists(index).Do(ctx)
		if err != nil {
			fmt.Printf("failed to check if index exists: %s\n", err)
			return
		}
		if !exists {
			// Create index if it doesn't exists
			createIndex, err := esclient.CreateIndex(index).BodyString(mapping).Do(ctx)
			if err != nil {
				fmt.Printf("failed to create index: %s\n", err)
				return
			}
			if !createIndex.Acknowledged {
				fmt.Printf("index creation not acknowledged: %s\n", err)
				return
			}
		}

		// Download logfile from S3
		logfile, err := downloadFromS3(record.S3.Bucket.Name, record.S3.Object.Key, record.AWSRegion)
		if err != nil {
			fmt.Printf("failed to get logfile from S3: %s\n", err)
			continue
		}

		// Decompress and parse logfile
		logEntries, err := gunzipAndParseLogfile(logfile)
		if err != nil {
			fmt.Printf("failed to decompress and parse logfile: %s\n", err)
			continue
		}

		// Insert logfile entries in ES
		err = insertEntriesInES(context.Background(), esclient, index, logEntries)
		if err != nil {
			fmt.Printf("failed to insert entries in elasticsearch: %s\n", err)
			continue
		}

		fmt.Printf("logfile %q inserted\n", record.S3.Object.Key)
	}
}

func downloadFromS3(bucket, key, region string) ([]byte, error) {

	// Create AWS session
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region)},
	)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to create aws session: %s", err)
	}

	// Buffer to store s3 object content
	object := aws.NewWriteAtBuffer([]byte{})

	// Download s3 object
	downloader := s3manager.NewDownloader(sess)
	_, err = downloader.Download(object,
		&s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
	if err != nil {
		return []byte{}, fmt.Errorf("unable to download item %q in bucket %q: %s", key, bucket, err)
	}

	return object.Bytes(), nil
}

func gunzipAndParseLogfile(logfile []byte) ([]*LogEntry, error) {

	// Create reader of logfile []byte
	logfileReader := bytes.NewReader(logfile)

	// Gunzip log file
	r, err := gzip.NewReader(logfileReader)
	if err != nil {
		return []*LogEntry{}, err
	}

	// Set GoCSV to use space as delimiter
	gocsv.SetCSVReader(func(in io.Reader) gocsv.CSVReader {
		r := csv.NewReader(in)
		r.Comma = ' '
		return r
	})

	// Unmarshal log file in structs
	entries := []*LogEntry{}
	err = gocsv.Unmarshal(r, &entries)
	if err != nil {
		return []*LogEntry{}, err
	}

	return entries, nil
}

func insertEntriesInES(ctx context.Context, client *elastic.Client, index string, entries []*LogEntry) error {

	bulkRequest := client.Bulk()

	for _, entry := range entries {

		// Ignore invalid entries
		if entry.LogStatus != "OK" {
			continue
		}
		if entry.Type != "IPv4" {
			continue
		}
		if entry.Action != "ACCEPT" {
			continue
		}

		// Add index request to bulk request
		indexReq := elastic.NewBulkIndexRequest().Index(index).Doc(entry)
		bulkRequest = bulkRequest.Add(indexReq)
	}

	// Skip if there is no entry to index
	if bulkRequest.NumberOfActions() == 0 {
		return nil
	}

	// Bulk index entries
	_, err := bulkRequest.Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to bulk index entries: %s", err)
	}

	// Flush to make sure the documents got written.
	_, err = client.Flush().Index(index).Do(ctx)
	if err != nil {
		return fmt.Errorf("failed to flush index: %s", err)
	}

	return nil
}
