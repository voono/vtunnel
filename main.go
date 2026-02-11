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
	"strings"
	"sync"
	"time"

	"github.com/armon/go-socks5"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/pbkdf2"
)

const (
	salt         = "raw-tcp-tunnel-handshake-v5"
	dataShards   = 10
	parityShards = 3
	mtuLimit     = 1200
	
	// فواصل زمانی تغییر پورت
	hopMinInterval = 45
	hopMaxInterval = 90

	// پرچم‌های TCP
	TCP_FIN = 0x01
	TCP_SYN = 0x02
	TCP_RST = 0x04
	TCP_PSH = 0x08
	TCP_ACK = 0x10
)

var bufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 4096)
	},
}

func main() {
	mode := flag.String("mode", "server", "Mode: 'server' or 'client'")
	listen := flag.String("listen", "", "SOCKS5 Listen Address")
	fwd := flag.String("fwd", "", "Port Forwarding")
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
			log.Fatal("Client mode requires -remote <IP>")
		}
		runClient(*listen, *fwd, *remote, *port, block)
	}
}

// ==========================================
//              SERVER LOGIC
// ==========================================

func runServer(port int, block kcp.BlockCrypt) {
	log.Printf("🚀 [Server] Handshake-Aware Tunnel starting on Port %d...", port)

	rawConn, err := NewRawTCPConn(port, 0, "server", "")
	if err != nil {
		log.Fatalf("Socket Error: %v", err)
	}

	listener, err := kcp.ServeConn(block, dataShards, parityShards, rawConn)
	if err != nil {
		log.Fatal(err)
	}

	listener.SetDSCP(46)
	listener.SetReadBuffer(16 * 1024 * 1024)
	listener.SetWriteBuffer(16 * 1024 * 1024)

	socksConf := &socks5.Config{Logger: log.New(os.Stderr, "[SOCKS] ", log.LstdFlags)}
	socksServer, _ := socks5.New(socksConf)

	for {
		sess, err := listener.Accept()
		if err != nil {
			continue
		}

		conn := sess.(*kcp.UDPSession)
		conn.SetStreamMode(true)
		conn.SetWindowSize(1024, 1024)
		conn.SetNoDelay(1, 20, 1, 1)
		conn.SetACKNoDelay(true)
		conn.SetMtu(mtuLimit)
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		smuxConf := smux.DefaultConfig()
		smuxConf.KeepAliveInterval = 5 * time.Second
		smuxConf.KeepAliveTimeout = 15 * time.Second

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
			s.SetReadDeadline(time.Now().Add(5 * time.Minute))

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

			pipe(s, remoteConn)
		}(stream)
	}
}

// ==========================================
//              CLIENT LOGIC
// ==========================================

func runClient(socksAddr, fwdRule, remoteIP string, remotePort int, block kcp.BlockCrypt) {
	log.Printf("🚀 [Client] Connecting with TCP Handshake Simulation...")

	hoppingConn, err := NewHoppingPacketConn(remoteIP, remotePort)
	if err != nil {
		log.Fatalf("Init Error: %v", err)
	}
	
	go hoppingConn.StartRotation()

	kcpSess, err := kcp.NewConn(fmt.Sprintf("%s:%d", remoteIP, remotePort), block, dataShards, parityShards, hoppingConn)
	if err != nil {
		log.Fatal(err)
	}

	kcpSess.SetStreamMode(true)
	kcpSess.SetWindowSize(1024, 1024)
	kcpSess.SetNoDelay(1, 20, 1, 1)
	kcpSess.SetACKNoDelay(true)
	kcpSess.SetMtu(mtuLimit)
	kcpSess.SetReadBuffer(16 * 1024 * 1024)
	kcpSess.SetWriteBuffer(16 * 1024 * 1024)

	smuxConf := smux.DefaultConfig()
	smuxConf.KeepAliveInterval = 5 * time.Second 
	smuxConf.KeepAliveTimeout = 20 * time.Second

	session, err := smux.Client(kcpSess, smuxConf)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	go func() {
		for {
			time.Sleep(2 * time.Second)
			if session.IsClosed() {
				log.Println("Session Closed -> Restarting")
				os.Exit(1)
			}
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

	select {}
}

func startListener(localAddr, targetAddr string, session *smux.Session) {
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Printf("Failed to listen on %s: %v", localAddr, err)
		return
	}
	log.Printf("✅ [Client] Ready: %s", localAddr)

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
		}(p1)
	}
}

func pipe(c1, c2 io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.CopyBuffer(c1, c2, make([]byte, 4096)); c1.Close() }()
	go func() { defer wg.Done(); io.CopyBuffer(c2, c1, make([]byte, 4096)); c2.Close() }()
	wg.Wait()
}

// ==========================================
//       HOPPING PACKET CONN
// ==========================================

type HoppingPacketConn struct {
	mu          sync.RWMutex
	activeConn  *RawTCPConn
	remoteIP    string
	remotePort  int
	isClosed    bool
}

func NewHoppingPacketConn(remoteIP string, remotePort int) (*HoppingPacketConn, error) {
	initialPort := rand.Intn(10000) + 40000
	
	// اینجا کانکشن را می‌سازیم، که شامل هندشیک هم می‌شود (در NewRawTCPConn)
	conn, err := NewRawTCPConn(initialPort, remotePort, "client", remoteIP)
	if err != nil {
		return nil, err
	}

	return &HoppingPacketConn{
		activeConn: conn,
		remoteIP:   remoteIP,
		remotePort: remotePort,
	}, nil
}

func (h *HoppingPacketConn) StartRotation() {
	for {
		waitSec := rand.Intn(hopMaxInterval-hopMinInterval) + hopMinInterval
		time.Sleep(time.Duration(waitSec) * time.Second)

		if h.isClosed {
			return
		}

		newPort := rand.Intn(15000) + 35000
		
		// کانکشن جدید = هندشیک جدید
		newConn, err := NewRawTCPConn(newPort, h.remotePort, "client", h.remoteIP)
		if err != nil {
			log.Printf("Rotation Failed: %v", err)
			continue
		}

		h.mu.Lock()
		oldConn := h.activeConn
		h.activeConn = newConn
		h.mu.Unlock()

		log.Printf("♻️ [Hopping] Switched to Source Port: %d (Handshake Complete)", newPort)

		go func(old *RawTCPConn) {
			time.Sleep(2 * time.Second)
			old.Close()
		}(oldConn)
	}
}

func (h *HoppingPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		h.mu.RLock()
		conn := h.activeConn
		h.mu.RUnlock()

		if h.isClosed {
			return 0, nil, io.EOF
		}

		n, addr, err = conn.ReadFrom(p)
		if err != nil {
			if strings.Contains(err.Error(), "closed network connection") {
				continue
			}
			return n, addr, err
		}
		return n, addr, nil
	}
}

func (h *HoppingPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.activeConn.WriteTo(p, addr)
}

func (h *HoppingPacketConn) Close() error {
	h.isClosed = true
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.activeConn.Close()
}

func (h *HoppingPacketConn) LocalAddr() net.Addr {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.activeConn.LocalAddr()
}

func (h *HoppingPacketConn) SetDeadline(t time.Time) error      { return nil }
func (h *HoppingPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (h *HoppingPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// ==========================================
//       RAW SOCKET WITH HANDSHAKE
// ==========================================

type RawTCPConn struct {
	conn       *net.IPConn
	localPort  int
	remotePort int
	remoteIP   net.IP
	mode       string
	
	// برای هندشیک
	seq uint32
	ack uint32
}

func NewRawTCPConn(localPort, remotePort int, mode, remoteIPStr string) (*RawTCPConn, error) {
	conn, err := net.ListenIP("ip4:tcp", nil)
	if err != nil {
		return nil, err
	}
	conn.SetReadBuffer(16 * 1024 * 1024)
	conn.SetWriteBuffer(16 * 1024 * 1024)

	var rip net.IP
	if remoteIPStr != "" {
		rip = net.ParseIP(remoteIPStr)
	}

	raw := &RawTCPConn{
		conn:       conn,
		localPort:  localPort,
		remotePort: remotePort,
		remoteIP:   rip,
		mode:       mode,
		seq:        rand.Uint32(),
	}

	// اگر کلاینت هستیم، هندشیک را انجام بده
	if mode == "client" {
		if err := raw.performHandshake(); err != nil {
			conn.Close()
			return nil, err
		}
	}

	return raw, nil
}

// کلاینت: انجام هندشیک 3 مرحله‌ای
func (c *RawTCPConn) performHandshake() error {
	// 1. ارسال SYN
	// log.Printf("Sending SYN from %d...", c.localPort)
	synPacket := MakeTCPHeader(c.localPort, c.remotePort, c.seq, 0, TCP_SYN, nil)
	if _, err := c.conn.WriteToIP(synPacket, &net.IPAddr{IP: c.remoteIP}); err != nil {
		return err
	}

	// 2. انتظار برای SYN-ACK
	buf := make([]byte, 1024)
	c.conn.SetReadDeadline(time.Now().Add(3 * time.Second)) // تایم اوت کوتاه
	defer c.conn.SetReadDeadline(time.Time{})

	for {
		n, src, err := c.conn.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("handshake timeout: %v", err)
		}
		
		// بررسی پورت و فلگ
		if n > 20 {
			srcPort := binary.BigEndian.Uint16(buf[0:2])
			dstPort := binary.BigEndian.Uint16(buf[2:4])
			flags := buf[13]

			if int(srcPort) == c.remotePort && int(dstPort) == c.localPort {
				// چک کردن SYN-ACK (0x12)
				if flags&TCP_SYN != 0 && flags&TCP_ACK != 0 {
					// دریافت شد!
					serverSeq := binary.BigEndian.Uint32(buf[4:8])
					c.ack = serverSeq + 1
					c.seq++
					
					// 3. ارسال ACK نهایی
					// log.Printf("Got SYN-ACK, sending ACK...")
					ackPacket := MakeTCPHeader(c.localPort, c.remotePort, c.seq, c.ack, TCP_ACK, nil)
					c.conn.WriteToIP(ackPacket, &net.IPAddr{IP: src.(*net.IPAddr).IP})
					return nil
				}
			}
		}
	}
}

func (c *RawTCPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)

	for {
		n, src, err := c.conn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < 20 {
			continue
		}

		packetDstPort := binary.BigEndian.Uint16(buf[2:4])
		packetSrcPort := binary.BigEndian.Uint16(buf[0:2])
		flags := buf[13]

		if int(packetDstPort) != c.localPort {
			continue
		}

		fakeUDPAddr := &net.UDPAddr{
			IP:   src.(*net.IPAddr).IP,
			Port: int(packetSrcPort),
		}

		// === SERVER HANDSHAKE LOGIC ===
		// اگر سرور هستیم و SYN دیدیم، باید SYN-ACK بدهیم
		if c.mode == "server" {
			if flags&TCP_SYN != 0 {
				// درخواست اتصال جدید است
				clientSeq := binary.BigEndian.Uint32(buf[4:8])
				// پاسخ SYN-ACK
				// log.Printf("Responding to SYN from %v", src)
				synAck := MakeTCPHeader(c.localPort, int(packetSrcPort), rand.Uint32(), clientSeq+1, TCP_SYN|TCP_ACK, nil)
				c.conn.WriteToIP(synAck, &net.IPAddr{IP: src.(*net.IPAddr).IP})
				continue // پکت را به لایه KCP نده
			}
			// اگر فقط ACK خالی بود (مرحله سوم هندشیک)، نادیده بگیر
			if flags&TCP_ACK != 0 && n == 20 {
				continue 
			}
		}

		// === DATA PACKET ===
		// فقط پکت‌های دیتا (که PSH دارند یا پیلود دارند) را برگردان
		// معمولا KCP پکت هایش PSH دارد یا طولش > 20 است
		if n > 20 {
			copy(p, buf[20:n])
			return n - 20, fakeUDPAddr, nil
		}
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

	// ارسال دیتا همیشه با PSH | ACK انجام می‌شود (بعد از هندشیک)
	packet := MakeTCPHeader(c.localPort, dstPort, c.seq, c.ack, TCP_PSH|TCP_ACK, p)
	
	// افزایش Seq به اندازه دیتای ارسالی (اختیاری برای فیک تی سی پی)
	// c.seq += uint32(len(p)) 

	_, err = c.conn.WriteToIP(packet, &net.IPAddr{IP: dstIP})
	return len(p), err
}

// تابع ساخت هدر منعطف
func MakeTCPHeader(srcPort, dstPort int, seq, ack uint32, flags byte, payload []byte) []byte {
	headerLen := 20
	totalLen := headerLen + len(payload)
	b := make([]byte, totalLen)

	binary.BigEndian.PutUint16(b[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(b[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(b[4:8], seq)
	binary.BigEndian.PutUint32(b[8:12], ack)
	
	b[12] = 0x50 // Data Offset (5 * 4 = 20 bytes)
	b[13] = flags
	binary.BigEndian.PutUint16(b[14:16], 65535) // Window Size

	if len(payload) > 0 {
		copy(b[20:], payload)
	}
	
	// محاسبه Checksum (اختیاری برای Raw Socket در برخی سیستم‌ها، اما بهتر است باشد)
	// در اینجا چون کرنل معمولاً هندل می‌کند یا Raw IP است، ساده رد می‌شویم.
	// برای واقعی‌تر شدن می‌توان Checksum فیک هم گذاشت.
	
	return b
}

func (c *RawTCPConn) Close() error                       { return c.conn.Close() }
func (c *RawTCPConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: c.localPort} }
func (c *RawTCPConn) SetDeadline(t time.Time) error      { return nil }
func (c *RawTCPConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *RawTCPConn) SetWriteDeadline(t time.Time) error { return nil }