package main

import (
	"crypto/sha1"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-socks5"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/pbkdf2"
)

const (
	salt         = "raw-tcp-tunnel-dual-mode"
	dataShards   = 10
	parityShards = 3
	mtuLimit     = 1200 // small MTU — avoids fragmentation and DPI flags on restricted networks
)

// copyBufPool — 16KB buffers for pipe() data transfer
var copyBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 16*1024)
		return &buf
	},
}

// rawReadBufPool — 64KB buffers for raw socket reads (max IP packet size)
var rawReadBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 65536)
		return &buf
	},
}

// writeBufPool — reusable buffers for WriteTo to avoid per-packet allocation
var writeBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 20+mtuLimit+100) // TCP header + max payload + margin
		return &buf
	},
}

// smuxConfig returns a tuned smux configuration for restricted/lossy networks (GFW, Iran).
// Priority: low latency, fast dead-peer detection, avoid bufferbloat.
func smuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.Version = 1
	cfg.KeepAliveInterval = 5 * time.Second   // detect dead peers quickly
	cfg.KeepAliveTimeout = 15 * time.Second    // fail fast on dead connections
	cfg.MaxFrameSize = 4096                    // small frames — less head-of-line blocking, lower latency
	cfg.MaxReceiveBuffer = 2 * 1024 * 1024     // 2MB session buffer — enough for bursts, avoids bloat
	cfg.MaxStreamBuffer = 256 * 1024           // 256KB per stream — prevents queuing on slow links
	return cfg
}

// applyKCPTuning applies consistent KCP settings tuned for restricted/lossy networks.
// Both client and server MUST use identical values for proper flow control.
//
// Design rationale for GFW/Iran:
//   - Small window (512) = less data in-flight = less queuing on throttled links
//   - interval=10ms = fast internal clock for quick retransmit
//   - resend=2 = aggressive fast retransmit after 2 dup ACKs (critical for high loss)
//   - nc=1 = no congestion control (GFW throttling would falsely trigger CC and kill speed)
//   - ACKNoDelay = flush ACKs immediately instead of batching (saves 1 RTT per ACK)
func applyKCPTuning(conn *kcp.UDPSession) {
	conn.SetStreamMode(true)
	conn.SetNoDelay(1, 10, 2, 1)
	conn.SetWindowSize(512, 512)
	conn.SetACKNoDelay(true)
	conn.SetMtu(mtuLimit)
	conn.SetReadBuffer(4 * 1024 * 1024)  // 4MB — enough for bursts, avoids OS-level bufferbloat
	conn.SetWriteBuffer(4 * 1024 * 1024)
}

func main() {
	mode := flag.String("mode", "server", "Mode: 'server' or 'client'")
	listen := flag.String("listen", "", "SOCKS5 Listen Address (e.g. :1080)")
	fwd := flag.String("fwd", "", "Port Forwarding: 'LocalPort:RemoteIP:RemotePort'")
	remote := flag.String("remote", "", "Server IP")
	port := flag.Int("port", 443, "Tunnel Port")
	key := flag.String("key", "secret", "Encryption key")
	flag.Parse()

	pass := pbkdf2.Key([]byte(*key), []byte(salt), 4096, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(pass)

	if *mode == "server" {
		runServer(*port, block)
	} else {
		if *remote == "" {
			log.Fatal("Client mode requires -remote <IP>")
		}
		runClient(*listen, *fwd, *remote, *port, block)
	}
}

// ==========================================
//              SERVER LOGIC
// ==========================================

func runServer(port int, block kcp.BlockCrypt) {
	log.Printf("[Server] Dual-Mode Tunnel starting on Port %d...", port)

	rawConn, err := NewRawTCPConn(port, 0, "server", "")
	if err != nil {
		log.Fatalf("Socket Error: %v", err)
	}

	listener, err := kcp.ServeConn(block, dataShards, parityShards, rawConn)
	if err != nil {
		log.Fatal(err)
	}

	listener.SetDSCP(46)
	listener.SetReadBuffer(4 * 1024 * 1024)
	listener.SetWriteBuffer(4 * 1024 * 1024)

	socksConf := &socks5.Config{Logger: log.New(os.Stderr, "[SOCKS] ", log.LstdFlags)}
	socksServer, _ := socks5.New(socksConf)

	for {
		sess, err := listener.Accept()
		if err != nil {
			log.Printf("[Server] Accept error: %v", err)
			continue
		}

		conn := sess.(*kcp.UDPSession)
		applyKCPTuning(conn)

		mux, err := smux.Server(sess, smuxConfig())
		if err != nil {
			log.Printf("[Server] Smux error: %v", err)
			continue
		}

		go handleMux(mux, socksServer)
	}
}

func handleMux(mux *smux.Session, socksServer *socks5.Server) {
	defer mux.Close()
	for {
		stream, err := mux.AcceptStream()
		if err != nil {
			return
		}
		go func(s *smux.Stream) {
			defer s.Close()

			lenBuf := make([]byte, 1)
			if _, err := io.ReadFull(s, lenBuf); err != nil {
				return
			}
			addrLen := int(lenBuf[0])

			if addrLen == 0 {
				socksServer.ServeConn(s)
				return
			}

			addrBuf := make([]byte, addrLen)
			if _, err := io.ReadFull(s, addrBuf); err != nil {
				return
			}
			targetAddr := string(addrBuf)

			remoteConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
			if err != nil {
				return
			}
			defer remoteConn.Close()

			// Set TCP_NODELAY on the outbound connection for lower latency
			if tc, ok := remoteConn.(*net.TCPConn); ok {
				tc.SetNoDelay(true)
			}

			pipe(s, remoteConn)
		}(stream)
	}
}

// ==========================================
//              CLIENT LOGIC
// ==========================================

func runClient(socksAddr, fwdRule, remoteIP string, remotePort int, block kcp.BlockCrypt) {
	for {
		session := connectToServer(remoteIP, remotePort, block)
		if session == nil {
			log.Printf("[Client] Connection failed, retrying in 3s...")
			time.Sleep(3 * time.Second)
			continue
		}

		log.Printf("[Client] Connected to %s:%d", remoteIP, remotePort)

		// Channel to signal when session dies
		done := make(chan struct{})

		// Start listeners only once — they re-open streams on the current session
		if socksAddr != "" {
			go startListener(socksAddr, "", session, done)
		}

		if fwdRule != "" {
			rules := strings.Split(fwdRule, ",")
			for _, rule := range rules {
				parts := strings.SplitN(rule, ":", 2)
				if len(parts) == 2 {
					localPort := parts[0]
					targetAddr := parts[1]
					go startListener(":"+localPort, targetAddr, session, done)
				} else {
					log.Printf("[Error] Invalid fwd rule: %s", rule)
				}
			}
		}

		// Monitor session health
		monitorSession(session, done)

		log.Printf("[Client] Session lost, reconnecting in 2s...")
		time.Sleep(2 * time.Second)
	}
}

func connectToServer(remoteIP string, remotePort int, block kcp.BlockCrypt) *smux.Session {
	localSrcPort := rand.IntN(10000) + 50000
	rawConn, err := NewRawTCPConn(localSrcPort, remotePort, "client", remoteIP)
	if err != nil {
		log.Printf("[Client] Socket Error: %v", err)
		return nil
	}

	kcpSess, err := kcp.NewConn(fmt.Sprintf("%s:%d", remoteIP, remotePort), block, dataShards, parityShards, rawConn)
	if err != nil {
		log.Printf("[Client] KCP Error: %v", err)
		return nil
	}

	applyKCPTuning(kcpSess)
	kcpSess.SetDSCP(46) // EF (Expedited Forwarding) — priority QoS

	session, err := smux.Client(kcpSess, smuxConfig())
	if err != nil {
		log.Printf("[Client] Smux Error: %v", err)
		kcpSess.Close()
		return nil
	}

	return session
}

func monitorSession(session *smux.Session, done chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		<-ticker.C
		if session.IsClosed() {
			close(done)
			return
		}
	}
}

func startListener(localAddr, targetAddr string, session *smux.Session, done chan struct{}) {
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Printf("Failed to listen on %s: %v", localAddr, err)
		return
	}
	defer ln.Close()

	mode := "SOCKS5"
	if targetAddr != "" {
		mode = fmt.Sprintf("Forward -> %s", targetAddr)
	}
	log.Printf("[Client] Service Ready: %s on %s", mode, localAddr)

	// Close the listener when the session dies so Accept() unblocks
	go func() {
		<-done
		ln.Close()
	}()

	for {
		p1, err := ln.Accept()
		if err != nil {
			select {
			case <-done:
				return // session died, exit cleanly
			default:
			}
			continue
		}
		go handleLocalConn(p1, targetAddr, session)
	}
}

func handleLocalConn(local net.Conn, targetAddr string, session *smux.Session) {
	p2, err := session.OpenStream()
	if err != nil {
		local.Close()
		return
	}

	if targetAddr == "" {
		p2.Write([]byte{0})
	} else {
		addrBytes := []byte(targetAddr)
		if len(addrBytes) > 255 {
			local.Close()
			p2.Close()
			return
		}
		p2.Write([]byte{byte(len(addrBytes))})
		p2.Write(addrBytes)
	}

	pipe(local, p2)
}

// pipe bidirectionally copies data between two connections using pooled 16KB buffers.
func pipe(p1, p2 io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	halfClose := func(dst, src io.ReadWriteCloser) {
		defer wg.Done()
		bufp := copyBufPool.Get().(*[]byte)
		defer copyBufPool.Put(bufp)
		io.CopyBuffer(dst, src, *bufp)
		// Signal write-close if supported; otherwise hard close
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go halfClose(p1, p2)
	go halfClose(p2, p1)
	wg.Wait()
	p1.Close()
	p2.Close()
}

// ==========================================
//       RAW SOCKET (OPTIMIZED)
// ==========================================

type RawTCPConn struct {
	conn       *net.IPConn
	localPort  int
	remotePort int
	remoteIP   net.IP
	mode       string
}

func NewRawTCPConn(localPort, remotePort int, mode, remoteIPStr string) (*RawTCPConn, error) {
	conn, err := net.ListenIP("ip4:tcp", nil)
	if err != nil {
		return nil, err
	}
	conn.SetReadBuffer(4 * 1024 * 1024)
	conn.SetWriteBuffer(4 * 1024 * 1024)

	var rip net.IP
	if remoteIPStr != "" {
		rip = net.ParseIP(remoteIPStr)
	}

	return &RawTCPConn{
		conn:       conn,
		localPort:  localPort,
		remotePort: remotePort,
		remoteIP:   rip,
		mode:       mode,
	}, nil
}

func (c *RawTCPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	bufp := rawReadBufPool.Get().(*[]byte)
	defer rawReadBufPool.Put(bufp)
	buf := *bufp

	for {
		n, src, err := c.conn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n <= 20 {
			continue
		}

		packetDstPort := binary.BigEndian.Uint16(buf[2:4])
		packetSrcPort := binary.BigEndian.Uint16(buf[0:2])

		if int(packetDstPort) != c.localPort {
			continue
		}

		payloadLen := n - 20
		copy(p, buf[20:n])

		fakeUDPAddr := &net.UDPAddr{
			IP:   src.(*net.IPAddr).IP,
			Port: int(packetSrcPort),
		}

		return payloadLen, fakeUDPAddr, nil
	}
}

func (c *RawTCPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var dstIP net.IP
	var dstPort int

	if c.mode == "client" {
		dstIP = c.remoteIP
		dstPort = c.remotePort
	} else {
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			dstIP = udpAddr.IP
			dstPort = udpAddr.Port
		} else {
			return 0, fmt.Errorf("addr error")
		}
	}

	// Use pooled buffer to avoid allocation on every write
	bufp := writeBufPool.Get().(*[]byte)
	defer writeBufPool.Put(bufp)
	packet := *bufp

	// Build TCP header directly into pooled buffer
	binary.BigEndian.PutUint16(packet[0:2], uint16(c.localPort))
	binary.BigEndian.PutUint16(packet[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(packet[4:8], rand.Uint32())
	binary.BigEndian.PutUint32(packet[8:12], rand.Uint32())
	packet[12] = 0x50 // data offset: 5 words (20 bytes)
	packet[13] = 0x18 // ACK + PSH flags
	binary.BigEndian.PutUint16(packet[14:16], 65535) // window size
	packet[16] = 0    // checksum (zeroed)
	packet[17] = 0
	packet[18] = 0    // urgent pointer
	packet[19] = 0

	// Copy payload after header
	copy(packet[20:], p)

	_, err = c.conn.WriteToIP(packet[:20+len(p)], &net.IPAddr{IP: dstIP})
	return len(p), err
}

func (c *RawTCPConn) Close() error                       { return c.conn.Close() }
func (c *RawTCPConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: c.localPort} }
func (c *RawTCPConn) SetDeadline(t time.Time) error      { return nil }
func (c *RawTCPConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *RawTCPConn) SetWriteDeadline(t time.Time) error { return nil }
