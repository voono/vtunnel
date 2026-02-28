package main

import (
	"crypto/sha1"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-socks5"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/pbkdf2"
)

const (
	salt         = "raw-tcp-tunnel-stable-v4"
	dataShards   = 10
	parityShards = 3
	mtuLimit     = 1200
	idleTimeout  = 60 * time.Second
	checkInterval = 5 * time.Second
)

var bufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 4096)
	},
}

func main() {
	mode := flag.String("mode", "server", "Mode: 'server' or 'client'")
	listen := flag.String("listen", "", "SOCKS5 Listen Address")
	fwd := flag.String("fwd", "", "Local Port Forwarding (e.g. 8080:target:80)")
	rev := flag.String("rev", "", "Reverse Port Forwarding (e.g. 8080:127.0.0.1:80)")
	remote := flag.String("remote", "", "Server IP")
	port := flag.Int("port", 443, "Tunnel Port")
	key := flag.String("key", "secret", "Encryption key")
	flag.Parse()

	rand.Seed(time.Now().UnixNano())

	pass := pbkdf2.Key([]byte(*key), []byte(salt), 4096, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(pass)

	if *mode == "server" {
		runServer(*port, block)
	} else {
		if *remote == "" {
			log.Fatal("❌ Client mode requires -remote <IP>")
		}
		runClient(*listen, *fwd, *rev, *remote, *port, block)
	}
}

// ==========================================
//              SERVER LOGIC
// ==========================================

func runServer(port int, block kcp.BlockCrypt) {
	log.Printf("🚀 [SERVER] Starting on Port %d", port)

	rawConn, err := NewRawTCPConn(port, 0, "server", "")
	if err != nil {
		log.Fatalf("❌ Socket Error: %v", err)
	}

	listener, err := kcp.ServeConn(block, dataShards, parityShards, rawConn)
	if err != nil {
		log.Fatal(err)
	}

	socksConf := &socks5.Config{Logger: log.New(os.Stderr, "[SOCKS] ", log.LstdFlags)}
	socksServer, _ := socks5.New(socksConf)

	for {
		sess, err := listener.Accept()
		if err != nil {
			continue
		}

		conn := sess.(*kcp.UDPSession)
		conn.SetStreamMode(true)
		conn.SetWindowSize(4096, 4096)
		conn.SetNoDelay(1, 10, 2, 1)
		conn.SetMtu(mtuLimit)
		conn.SetACKNoDelay(true)

		smuxConf := smux.DefaultConfig()
		smuxConf.KeepAliveInterval = 5 * time.Second
		smuxConf.KeepAliveTimeout = 15 * time.Second
		smuxConf.MaxFrameSize = 32768
		smuxConf.MaxReceiveBuffer = 4194304

		mux, err := smux.Server(sess, smuxConf)
		if err != nil {
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
			s.SetReadDeadline(time.Now().Add(idleTimeout))

			lenBuf := make([]byte, 1)
			if _, err := io.ReadFull(s, lenBuf); err != nil {
				return
			}
			addrLen := int(lenBuf[0])

			// Magic Byte 255: Reverse Tunnel Control Stream
			if addrLen == 255 {
				s.SetReadDeadline(time.Time{}) // Disable deadline for control stream

				portBuf := make([]byte, 2)
				if _, err := io.ReadFull(s, portBuf); err != nil {
					return
				}
				port := binary.BigEndian.Uint16(portBuf)

				tLenBuf := make([]byte, 1)
				if _, err := io.ReadFull(s, tLenBuf); err != nil {
					return
				}
				tLen := int(tLenBuf[0])
				tBuf := make([]byte, tLen)
				if _, err := io.ReadFull(s, tBuf); err != nil {
					return
				}
				targetAddr := string(tBuf)

				log.Printf("🔄 [SERVER] Reverse tunnel setup requested on port %d -> %s", port, targetAddr)

				ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
				if err != nil {
					log.Printf("❌ Failed to listen for reverse tunnel on %d: %v", port, err)
					return
				}
				defer ln.Close()

				// Monitor the control stream; if the client closes it, close the listener
				go func() {
					io.Copy(io.Discard, s)
					ln.Close()
				}()

				for {
					conn, err := ln.Accept()
					if err != nil {
						break
					}
					go func(c net.Conn) {
						defer c.Close()
						revStream, err := mux.OpenStream()
						if err != nil {
							return
						}
						defer revStream.Close()

						// Tell client where to route this locally
						revStream.Write([]byte{byte(len(targetAddr))})
						revStream.Write([]byte(targetAddr))
						pipe(c, revStream)
					}(conn)
				}
				return
			}

			// 0: SOCKS5 Request
			if addrLen == 0 {
				socksServer.ServeConn(s)
				return
			}

			// >0: Direct Forward Request
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

			pipe(s, remoteConn)
		}(stream)
	}
}

// ==========================================
//              CLIENT LOGIC
// ==========================================

func runClient(socksAddr, fwdRule, revRule, remoteIP string, remotePort int, block kcp.BlockCrypt) {
	localSrcPort := rand.Intn(10000) + 50000
	log.Printf("🚀 [CLIENT] Connecting to %s:%d (Local Port: %d)", remoteIP, remotePort, localSrcPort)

	rawConn, err := NewRawTCPConn(localSrcPort, remotePort, "client", remoteIP)
	if err != nil {
		log.Fatalf("❌ Socket Error: %v", err)
	}

	kcpSess, err := kcp.NewConn(fmt.Sprintf("%s:%d", remoteIP, remotePort), block, dataShards, parityShards, rawConn)
	if err != nil {
		log.Fatal(err)
	}

	kcpSess.SetStreamMode(true)
	kcpSess.SetWindowSize(4096, 4096)
	kcpSess.SetNoDelay(1, 10, 2, 1)
	kcpSess.SetMtu(mtuLimit)
	kcpSess.SetACKNoDelay(true)

	smuxConf := smux.DefaultConfig()
	smuxConf.KeepAliveInterval = 5 * time.Second
	smuxConf.KeepAliveTimeout = 15 * time.Second
	smuxConf.MaxFrameSize = 32768
	smuxConf.MaxReceiveBuffer = 4194304

	session, err := smux.Client(kcpSess, smuxConf)
	if err != nil {
		log.Printf("❌ Smux Error: %v", err)
		os.Exit(1)
	}

	// Watchdog
	go func() {
		ticker := time.NewTicker(checkInterval)
		for range ticker.C {
			if session.IsClosed() {
				log.Println("🔴 [RESTART] Smux session closed (Protocol Timeout).")
				os.Exit(1)
			}
		}
	}()

	// Handle incoming streams from the Server (used for Reverse Tunneling)
	go func() {
		for {
			stream, err := session.AcceptStream()
			if err != nil {
				return
			}
			go func(s *smux.Stream) {
				defer s.Close()
				s.SetReadDeadline(time.Now().Add(idleTimeout))

				lenBuf := make([]byte, 1)
				if _, err := io.ReadFull(s, lenBuf); err != nil {
					return
				}
				tLen := int(lenBuf[0])
				tBuf := make([]byte, tLen)
				if _, err := io.ReadFull(s, tBuf); err != nil {
					return
				}
				targetAddr := string(tBuf)

				localConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
				if err != nil {
					log.Printf("❌ Reverse dial failed to %s: %v", targetAddr, err)
					return
				}
				defer localConn.Close()

				pipe(s, localConn)
			}(stream)
		}
	}()

	if socksAddr != "" {
		go startListener(socksAddr, "", session)
	}

	if fwdRule != "" {
		rules := strings.Split(fwdRule, ",")
		for _, rule := range rules {
			parts := strings.SplitN(rule, ":", 2)
			if len(parts) == 2 {
				go startListener(":"+parts[0], parts[1], session)
			}
		}
	}

	// Setup Reverse Tunnels
	if revRule != "" {
		rules := strings.Split(revRule, ",")
		for _, rule := range rules {
			parts := strings.SplitN(rule, ":", 2)
			if len(parts) == 2 {
				port, err := strconv.Atoi(parts[0])
				if err == nil {
					go setupReverseTunnel(session, uint16(port), parts[1])
				}
			}
		}
	}

	select {}
}

func setupReverseTunnel(session *smux.Session, remotePort uint16, targetAddr string) {
	log.Printf("📡 [REVERSE] Telling server to listen on port %d -> forwarding to local %s", remotePort, targetAddr)
	
	s, err := session.OpenStream()
	if err != nil {
		log.Printf("❌ Reverse tunnel setup failed: %v", err)
		return
	}
	
	// Payload format: [255 (magic)] [remote port (2 bytes)] [target length (1 byte)] [target addr string]
	s.Write([]byte{255})
	
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, remotePort)
	s.Write(portBuf)

	addrBytes := []byte(targetAddr)
	s.Write([]byte{byte(len(addrBytes))})
	s.Write(addrBytes)

	// Keep stream open. If it closes, the server stops listening on that port.
	io.Copy(io.Discard, s)
	log.Printf("🔴 [REVERSE] Tunnel for %d closed", remotePort)
}

func startListener(localAddr, targetAddr string, session *smux.Session) {
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Printf("❌ Failed to listen on %s: %v", localAddr, err)
		return
	}
	log.Printf("✅ [LISTENER] Ready on %s", localAddr)

	for {
		p1, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(local net.Conn) {
			p2, err := session.OpenStream()
			if err != nil {
				local.Close()
				return
			}
			p2.SetReadDeadline(time.Now().Add(idleTimeout))

			if targetAddr == "" {
				p2.Write([]byte{0})
			} else {
				addrBytes := []byte(targetAddr)
				p2.Write([]byte{byte(len(addrBytes))})
				p2.Write(addrBytes)
			}
			pipe(local, p2)
		}(p1)
	}
}

func pipe(c1, c2 io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyLoop(c1, c2); c1.Close(); c2.Close() }()
	go func() { defer wg.Done(); copyLoop(c2, c1); c2.Close(); c1.Close() }()
	wg.Wait()
}

func copyLoop(src io.Reader, dst io.Writer) {
	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)
	for {
		if conn, ok := src.(interface{ SetReadDeadline(time.Time) error }); ok {
			conn.SetReadDeadline(time.Now().Add(idleTimeout))
		}
		nr, err := src.Read(buf)
		if nr > 0 {
			dst.Write(buf[0:nr])
		}
		if err != nil {
			break
		}
	}
}

// ==========================================
//              RAW SOCKET LOGIC
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
	return &RawTCPConn{conn: conn, localPort: localPort, remotePort: remotePort, remoteIP: rip, mode: mode}, nil
}

func (c *RawTCPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)

	for {
		c.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		
		n, src, err := c.conn.ReadFrom(buf)
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				return 0, nil, err
			}
			return 0, nil, err
		}

		if n <= 20 { continue }
		packetDstPort := binary.BigEndian.Uint16(buf[2:4])
		packetSrcPort := binary.BigEndian.Uint16(buf[0:2])

		if int(packetDstPort) != c.localPort { continue }

		copy(p, buf[20:n])
		return n - 20, &net.UDPAddr{IP: src.(*net.IPAddr).IP, Port: int(packetSrcPort)}, nil
	}
}

func (c *RawTCPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var dstIP net.IP
	var dstPort int
	if c.mode == "client" {
		dstIP, dstPort = c.remoteIP, c.remotePort
	} else {
		udp := addr.(*net.UDPAddr)
		dstIP, dstPort = udp.IP, udp.Port
	}

	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], uint16(c.localPort))
	binary.BigEndian.PutUint16(h[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(h[4:8], rand.Uint32())
	h[12], h[13] = 0x50, 0x18
	binary.BigEndian.PutUint16(h[14:16], 65535)

	_, err = c.conn.WriteToIP(append(h, p...), &net.IPAddr{IP: dstIP})
	return len(p), err
}

func (c *RawTCPConn) Close() error                       { return c.conn.Close() }
func (c *RawTCPConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: c.localPort} }
func (c *RawTCPConn) SetDeadline(t time.Time) error      { return nil }
func (c *RawTCPConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *RawTCPConn) SetWriteDeadline(t time.Time) error { return nil }