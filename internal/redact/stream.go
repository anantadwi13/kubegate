package redact

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

// maxFrameBytes bounds a single watch frame. bufio.Reader's ReadBytes has no
// limit of its own, so we impose one: an unbounded frame would let an
// upstream response drive host memory use.
const maxFrameBytes = 8 << 20 // 8 MiB, matching the request body cap

// Stream copies newline-delimited watch frames from src to dst, redacting
// each frame's object as it passes.
//
// flush, when non-nil, is called after every frame. Watch output must reach
// the client immediately: buffering would make kubectl get -w appear to
// hang.
//
// A frame that cannot be decoded aborts the stream with an error and is not
// forwarded. Failing open would void the mode's guarantee mid-stream, which
// is worse than a dropped connection because nothing would look wrong.
func Stream(dst io.Writer, src io.Reader, flush func()) error {
	br := bufio.NewReaderSize(src, 64<<10)
	for {
		line, err := readFrame(br)
		if len(line) > 0 {
			if werr := writeFrame(dst, line, flush); werr != nil {
				return werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// readFrame reads one newline-terminated frame, growing past the reader's
// buffer size as needed and refusing anything absurd.
func readFrame(br *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > maxFrameBytes {
			return nil, fmt.Errorf("watch frame exceeds %d bytes", maxFrameBytes)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return buf, err
	}
}

// writeFrame redacts a single frame and writes it, preserving the trailing
// newline the protocol requires.
func writeFrame(dst io.Writer, line []byte, flush func()) error {
	trimmed := trimSpace(line)
	if len(trimmed) == 0 {
		return nil
	}

	var frame map[string]any
	if err := json.Unmarshal(trimmed, &frame); err != nil {
		return fmt.Errorf("decoding watch frame: %w", err)
	}
	if obj, ok := frame["object"].(map[string]any); ok {
		Object(obj, "")
	}
	out, err := json.Marshal(frame)
	if err != nil {
		return fmt.Errorf("re-encoding watch frame: %w", err)
	}
	if _, err := dst.Write(append(out, '\n')); err != nil {
		return err
	}
	if flush != nil {
		flush()
	}
	return nil
}

func trimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && isSpace(b[start]) {
		start++
	}
	end := len(b)
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}
