package encrypt

import (
	"bytes"
	"compress/gzip"
)

/**
concurrrency compress
github.com/klauspost/pgzip
*/

// Write gzipped data to a Writer
func W3PGzip(data []byte) ([]byte, error) {
	// Write gzipped data to the client
	var buf bytes.Buffer

	// gzip
	//gw := gzip.NewWriter(&buf)
	gw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}

	/*
		// pgzip
		gw, err := pgzip.NewWriterLevel(&buf, pgzip.DefaultCompression)
		// 1MB block with 4 concurrency
		gw.SetConcurrency(1<<20, 4)
	*/

	//defer gw.Close()
	gw.Write(data)
	gw.Flush()
	gw.Close()

	return buf.Bytes(), err
}

// Write gunzipped data to a Writer
func W3PUngzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	// Write gzipped data to the client
	gr, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	//defer gr.Close()

	buf.ReadFrom(gr)
	gr.Close()
	return buf.Bytes(), nil
}
