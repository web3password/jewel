package encrypt

import (
	"bytes"
	"compress/zlib"
)

// Write gzipped data to a Writer
func W3PZlipCompress(data []byte) ([]byte, error) {
	// Write gzipped data to the client
	var buf bytes.Buffer

	// zlib
	//gw := gzip.NewWriter(&buf)
	gw, err := zlib.NewWriterLevel(&buf, zlib.DefaultCompression)
	if err != nil {
		return nil, err
	}

	//defer gw.Close()
	gw.Write(data)
	gw.Flush()
	gw.Close()

	return buf.Bytes(), err
}

// Write gunzipped data to a Writer
func W3PZlibUncompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	// Write gzipped data to the client
	gr, err := zlib.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	//defer gr.Close()

	buf.ReadFrom(gr)
	gr.Close()
	return buf.Bytes(), nil
}
