package proxy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/aagun1234/glider/pkg/pool"
	"github.com/aagun1234/glider/pkg/log"
)

var (
	// TCPBufSize is the size of tcp buffer.
	TCPBufSize = 32 << 10

	// UDPBufSize is the size of udp buffer.
	UDPBufSize = 2 << 10
	
)

// Conn is a connection with buffered reader.
type Conn struct {
	r *bufio.Reader
	net.Conn
	
}

// NewConn returns a new conn.
func NewConn(c net.Conn) *Conn {
	if conn, ok := c.(*Conn); ok {
		return conn
	}
	return &Conn{pool.GetBufReader(c), c}
}

// Reader returns the internal bufio.Reader.
func (c *Conn) Reader() *bufio.Reader      { return c.r }
func (c *Conn) Read(p []byte) (int, error) { return c.r.Read(p) }

// Peek returns the next n bytes without advancing the reader.
func (c *Conn) Peek(n int) ([]byte, error) { return c.r.Peek(n) }

// WriteTo implements io.WriterTo.
func (c *Conn) WriteTo(w io.Writer) (n int64, err error) { return c.r.WriteTo(w) }

// Close closes the Conn.
func (c *Conn) Close() error {
	pool.PutBufReader(c.r)
	return c.Conn.Close()
}

// Relay relays between left and right.
func Relay(left, right net.Conn) error {
	var err, err1 error
	var in_bytes		int64
	var out_bytes	int64
	var Inbytes		uint64
	var Outbytes	uint64

	var wg sync.WaitGroup
	var wait = 5 * time.Second

	wg.Add(1)
	go func() {
		defer wg.Done()
		in_bytes, err1 = Copy(right, left)
		Inbytes=Inbytes+uint64(in_bytes)
		right.SetReadDeadline(time.Now().Add(wait)) // unblock read on right
	}()

	out_bytes, err = Copy(left, right)
	Outbytes=Outbytes+uint64(out_bytes)
	left.SetReadDeadline(time.Now().Add(wait)) // unblock read on left
	wg.Wait()

	if err1 != nil && !errors.Is(err1, os.ErrDeadlineExceeded) {
		return err1
	}

	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}

	return nil
}
// Relay relays between left and right.
func Relay1(left, right net.Conn, rate int64) (uint64,uint64,error) {
	var err, err1 error
	var in_bytes		int64
	var out_bytes	int64
	var Inbytes		uint64
	var Outbytes	uint64

	var wg sync.WaitGroup
	var wait = 5 * time.Second

	wg.Add(1)
	go func() {
		defer wg.Done()
		in_bytes, err1 = Copy1(right, left, rate)
		Inbytes=Inbytes+uint64(in_bytes)
		right.SetReadDeadline(time.Now().Add(wait)) // unblock read on right
	}()

	out_bytes, err = Copy1(left, right, rate)
	Outbytes=Outbytes+uint64(out_bytes)
	left.SetReadDeadline(time.Now().Add(wait)) // unblock read on left
	wg.Wait()

	if err1 != nil && !errors.Is(err1, os.ErrDeadlineExceeded) {
		return Inbytes,Outbytes,err1
	}

	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		return Inbytes,Outbytes,err
	}

	return Inbytes,Outbytes,nil
}
// Copy copies from src to dst.
func Copy(dst io.Writer, src io.Reader) (written int64, err error) {
	dst = underlyingWriter(dst)
	switch runtime.GOOS {
	case "linux", "windows", "dragonfly", "freebsd", "solaris":
		if _, ok := dst.(*net.TCPConn); ok && worthTry(src) {
			if wt, ok := src.(io.WriterTo); ok {
				return wt.WriteTo(dst)
			}
			if rt, ok := dst.(io.ReaderFrom); ok {
				return rt.ReadFrom(src)
			}
		}
	}
	return CopyBuffer(dst, src)
}



// RateLimitedWriter wraps a Writer and limits the write rate.
type RateLimitedWriter struct {
	w          io.Writer
	limit      int64
	mu         sync.Mutex
	lastWrite  time.Time
	bytesLastWrite int64
}

func NewRateLimitedWriter(w io.Writer, limit int64) *RateLimitedWriter {
	return &RateLimitedWriter{
		w:          w,
		limit:      limit,
		lastWrite:  time.Now(),
	}
}

func (rlw *RateLimitedWriter) Write1(p []byte) (n int, err error) {
	rlw.mu.Lock()
	defer rlw.mu.Unlock()

	now := time.Now()
	sinceLastWrite := now.Sub(rlw.lastWrite)
	log.F("[conn]  RateLimit Write, ratelimit: %d, bytesLastWrite: %d, bytesToWrite: %d , Duration: %v", rlw.limit, rlw.bytesLastWrite, len(p), sinceLastWrite.Seconds())
	if rlw.bytesLastWrite+int64(len(p)) > int64(float64(rlw.limit)*sinceLastWrite.Seconds()) {
		secs:=(float64(rlw.bytesLastWrite+int64(len(p)))-float64(rlw.limit)*sinceLastWrite.Seconds())/float64(rlw.limit)
		log.F("[conn]  RateLimit Write, sleep: %v ", secs)
		time.Sleep(time.Duration(secs * float64(time.Second)))
		rlw.bytesLastWrite = 0
		now = time.Now()
	} else {
		rlw.bytesLastWrite = int64(len(p))
	}

	n, err = rlw.w.Write(p)
	if rlw.bytesLastWrite>0 && rlw.bytesLastWrite>int64(n) {
		rlw.bytesLastWrite=int64(n)
	}
	log.F("[conn]  RateLimit Write, bytesWrite: %d ",n)
	rlw.lastWrite = now
	return n, err
}

func (rlw *RateLimitedWriter) Write(p []byte) (n int, err error) {
	rlw.mu.Lock()
	defer rlw.mu.Unlock()


	n, err = rlw.w.Write(p)
	now := time.Now()
	log.F("[conn]  RateLimit Write, bytesWrite: %d ",n)
	sinceLastWrite := now.Sub(rlw.lastWrite)
	secs:=float64(n)-float64(rlw.limit)*sinceLastWrite.Seconds()
	log.F("[conn]  RateLimit Write, Duration: %v ", sinceLastWrite.Seconds())
	if secs>0 {
		secs=secs/float64(rlw.limit)
		log.F("[conn]  RateLimit Write, sleep: %v ", secs)
		time.Sleep(time.Duration(secs * float64(time.Second)))
	} 
	rlw.lastWrite = now
	
	
	return n, err
}

// RateLimitedReader wraps a Reader and limits the read rate.
type RateLimitedReader struct {
	r          io.Reader
	limit      int64
	mu         sync.Mutex
	lastRead   time.Time
	bytesLastRead int64
}

func NewRateLimitedReader(r io.Reader, limit int64) *RateLimitedReader {
	return &RateLimitedReader{
		r:          r,
		limit:      limit,
		lastRead:   time.Now(),
	}
}

func (rlr *RateLimitedReader) Read1(p []byte) (n int, err error) {
	rlr.mu.Lock()
	defer rlr.mu.Unlock()

	now := time.Now()
	sinceLastRead := now.Sub(rlr.lastRead)
	log.F("[conn]  RateLimit Write, ratelimit: %d, bytesLastWrite: %d, bytesToWrite: %d , Duration: %v", rlr.limit, rlr.bytesLastRead, len(p), sinceLastRead.Seconds())
	if rlr.bytesLastRead+int64(len(p)) > int64(float64(rlr.limit)*sinceLastRead.Seconds()) {
		secs:=(float64(rlr.bytesLastRead+int64(len(p)))-float64(rlr.limit)*sinceLastRead.Seconds())/float64(rlr.limit)
		log.F("[conn]  RateLimit Read, sleep: %v ", secs)
		time.Sleep(time.Duration(secs * float64(time.Second)))
		rlr.bytesLastRead = 0
		now = time.Now()
	} else {
		rlr.bytesLastRead = int64(len(p))
	}


	n, err = rlr.r.Read(p)
	if rlr.bytesLastRead>0 && rlr.bytesLastRead>int64(n) {
		rlr.bytesLastRead=int64(n)
	}
	log.F("[conn]  RateLimit Read, bytesRead: %d ", n)
	rlr.lastRead = now
	return n, err
}

func (rlr *RateLimitedReader) Read(p []byte) (n int, err error) {
	rlr.mu.Lock()
	defer rlr.mu.Unlock()

	n, err = rlr.r.Read(p)
	log.F("[conn]  RateLimit Read, bytesRead: %d ", n)
	now := time.Now()
	sinceLastRead := now.Sub(rlr.lastRead)

	secs:=float64(n)-float64(rlr.limit)*sinceLastRead.Seconds()
	log.F("[conn]  RateLimit Read, Duration: %v ", sinceLastRead.Seconds())
	if secs > 0 {
		secs:=secs/float64(rlr.limit)
		log.F("[conn]  RateLimit Read, sleep: %v ", secs)
		time.Sleep(time.Duration(secs * float64(time.Second)))	
	}
	rlr.lastRead = now
	
	return n, err
}

// Copy copies from src to dst.
func Copy1(dst io.Writer, src io.Reader,rateLimit int64) (written int64, err error) {
	dst = underlyingWriter(dst)
	switch runtime.GOOS {
	case "linux", "windows", "dragonfly", "freebsd", "solaris":
		if _, ok := dst.(*net.TCPConn); ok && worthTry(src) {
			if wt, ok := src.(io.WriterTo); ok {
				
				limitedDst := NewRateLimitedWriter(dst, rateLimit)
				return wt.WriteTo(limitedDst)
				//return wt.WriteTo(dst)
			}
			if rt, ok := dst.(io.ReaderFrom); ok {
				
				limitedSrc := NewRateLimitedReader(src, rateLimit)
				return rt.ReadFrom(limitedSrc)
				//return rt.ReadFrom(src)
			}
		}
	}
	if rateLimit<=0 {
		log.F("[conn]  Copy without ratelimit")
		return CopyBuffer(dst, src)
	} else {
		log.F("[conn]  Copy with ratelimit: %d", rateLimit )
		return CopyBuffer1(dst, src,rateLimit)
	}
}


func underlyingWriter(c io.Writer) io.Writer {
	if wrap, ok := c.(*Conn); ok {
		return wrap.Conn
	}
	return c
}

func worthTry(src io.Reader) bool {
	switch v := src.(type) {
	case *net.TCPConn, *net.UnixConn:
		return true
	case *io.LimitedReader:
		return worthTry(v.R)
	case *Conn:
		return worthTry(v.Conn)
	case *os.File:
		fi, err := v.Stat()
		if err != nil {
			return false
		}
		return fi.Mode().IsRegular()
	default:
		return false
	}
}

// CopyN copies n bytes (or until an error) from src to dst.
func CopyN(dst io.Writer, src io.Reader, n int64) (written int64, err error) {
	written, err = Copy(dst, io.LimitReader(src, n))
	
	if written == n {
		return n, nil
	}
	if written < n && err == nil {
		// src stopped early; must have been EOF.
		err = io.EOF
	}
	return
}

// CopyBuffer copies from src to dst with a userspace buffer.
func CopyBuffer(dst io.Writer, src io.Reader) (written int64, err error) {
	size := TCPBufSize
	if l, ok := src.(*io.LimitedReader); ok && int64(size) > l.N {
		if l.N < 1 {
			size = 1
		} else {
			size = int(l.N)
		}
	}

	buf := pool.GetBuffer(size)
	defer pool.PutBuffer(buf)

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

type TokenBucket struct {
	rate    int64 // tokens per second
	burst   int64 // max number of tokens in the bucket
	tokens  int64 // current number of tokens in the bucket
	lastRef time.Time
	mu      sync.Mutex
}

func NewTokenBucket(rate, burst int64) *TokenBucket {
	return &TokenBucket{
		rate:    rate,
		burst:   burst,
		tokens:  burst,
		lastRef: time.Now(),
	}
}

func (tb *TokenBucket) Take(n int64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	sinceLast := now.Sub(tb.lastRef).Seconds()
	newTokens := int64(sinceLast * float64(tb.rate))
	if newTokens > 0 {
		tb.tokens = min(tb.tokens+newTokens, tb.burst)
	}
	tb.lastRef = now

	if n > tb.tokens {
		return false
	}
	tb.tokens -= n
	return true
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
// CopyBuffer copies from src to dst with a userspace buffer.
func CopyBuffer1(dst io.Writer, src io.Reader, rate int64) (written int64, err error) {
	size := TCPBufSize
	if l, ok := src.(*io.LimitedReader); ok && int64(size) > l.N {
		if l.N < 1 {
			size = 1
		} else {
			size = int(l.N)
		}
	}

	buf := pool.GetBuffer(size)
	defer pool.PutBuffer(buf)

	// Create a token bucket for rate limiting
	bucket := NewTokenBucket(rate, int64(size))

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			// Check if we have enough tokens to proceed
			if !bucket.Take(int64(nr)) {
				time.Sleep(time.Second / time.Duration(rate))
				log.F("[conn]  CopyBuffer ratelimit, sleep: %d", time.Second / time.Duration(rate) )
				continue
			}

			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

// CopyUDP copys from src to dst at target with read timeout.
// if step sets to non-zero value,
// the read timeout will be increased from 0 to timeout by step in every read operation.
func CopyUDP(dst net.PacketConn, writeTo net.Addr, src net.PacketConn, timeout time.Duration, step time.Duration) error {
	buf := pool.GetBuffer(UDPBufSize)
	defer pool.PutBuffer(buf)

	var t time.Duration
	for {
		if t += step; t == 0 || t > timeout {
			t = timeout
		}

		src.SetReadDeadline(time.Now().Add(t))
		n, addr, err := src.ReadFrom(buf)
		if err != nil {
			return err
		}

		if writeTo != nil {
			addr = writeTo
		}

		_, err = dst.WriteTo(buf[:n], addr)
		if err != nil {
			return err
		}
	}
}



func CopyUDP1(dst net.PacketConn, writeTo net.Addr, src net.PacketConn, timeout time.Duration, step time.Duration, rate int64) error {
	buf := pool.GetBuffer(UDPBufSize)
	defer pool.PutBuffer(buf)

	// Create a token bucket for rate limiting
	bucket := NewTokenBucket(rate, int64(UDPBufSize))

	var t time.Duration
	for {
		if t += step; t == 0 || t > timeout {
			t = timeout
		}

		src.SetReadDeadline(time.Now().Add(t))
		n, addr, err := src.ReadFrom(buf)
		if err != nil {
			return err
		}

		// Check if we have enough tokens to proceed
		if !bucket.Take(int64(n)) {
			time.Sleep(time.Second / time.Duration(rate))
			continue
		}

		if writeTo != nil {
			addr = writeTo
		}

		_, err = dst.WriteTo(buf[:n], addr)
		if err != nil {
			return err
		}
	}
}
