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
	salt           = "raw-tcp-tunnel-handshake-v7"
	dataShards     = 10
	parityShards   = 3
	mtuLimit       = 1200
	hopMinInterval = 60
	hopMaxInterval = 120
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
	log.Printf("🚀 [Server] Handshake-Aware Tunnel Ready on Port %d...", port)

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
		conn.SetReadDeadline(time.Now().Add(10 * time.Minute))

		smuxConf := smux.DefaultConfig()
		smuxConf.KeepAliveInterval = 5 * time.Second
		smuxConf.KeepAliveTimeout = 20 * time.Second

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
			s.SetReadDeadline(time.Now().Add(10 * time.Minute))

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
	log.Printf("🚀 [Client] Starting with Fake TCP Handshake...")

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
				log.Println("Session Closed -> Exiting")
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
//       HOPPING WITH FAKE HANDSHAKE
// ==========================================

type Packet struct {
	Data []byte
	Addr net.Addr
	Err  error
}

type HoppingPacketConn struct {
	mu           sync.RWMutex
	activeConn   *RawTCPConn
	readCh       chan Packet
	remoteIP     string
	remotePort   int
	isClosed     bool
}

func NewHoppingPacketConn(remoteIP string, remotePort int) (*HoppingPacketConn, error) {
	h := &HoppingPacketConn{
		readCh:     make(chan Packet, 2000), 
		remoteIP:   remoteIP,
		remotePort: remotePort,
	}

	conn, err := h.createNewConn()
	if err != nil {
		return nil, err
	}

	h.activeConn = conn
	go h.readLoop(conn)

	return h, nil
}

func (h *HoppingPacketConn) createNewConn() (*RawTCPConn, error) {
	port := rand.Intn(10000) + 40000
	return NewRawTCPConn(port, h.remotePort, "client", h.remoteIP)
}

func (h *HoppingPacketConn) readLoop(conn *RawTCPConn) {
	for {
		buf := make([]byte, 4096) 
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return 
		}
		// فیلتر کردن پکت‌های خالی یا هندشیک فیک
		if n == 0 { 
			continue 
		}

		select {
		case h.readCh <- Packet{Data: buf[:n], Addr: addr, Err: nil}:
		default:
		}
	}
}

// ارسال پکت‌های فیک برای گول زدن فایروال
func (h *HoppingPacketConn) sendFakeHandshake(conn *RawTCPConn) {
	// 1. ساخت پکت SYN
	// فلگ SYN = 0x02
	synPacket := MakeTCPHeaderCustom(conn.localPort, h.remotePort, 0x02, nil) 
	
	// ارسال SYN
	dstIP := net.ParseIP(h.remoteIP)
	conn.conn.WriteToIP(synPacket, &net.IPAddr{IP: dstIP})

	// 2. کمی صبر (شبیه‌سازی RTT)
	time.Sleep(50 * time.Millisecond)

	// 3. ساخت پکت ACK
	// فلگ ACK = 0x10
	ackPacket := MakeTCPHeaderCustom(conn.localPort, h.remotePort, 0x10, nil)
	conn.conn.WriteToIP(ackPacket, &net.IPAddr{IP: dstIP})
	
	// حالا کانکشن از نظر فایروال "ESTABLISHED" است
}


func (h *HoppingPacketConn) StartRotation() {
	for {
		waitSec := rand.Intn(hopMaxInterval-hopMinInterval) + hopMinInterval
		time.Sleep(time.Duration(waitSec) * time.Second)

		if h.isClosed {
			return
		}

		newConn, err := h.createNewConn()
		if err != nil {
			log.Printf("Rotation Failed: %v", err)
			continue
		}

		// *** MAGIC HAPPENS HERE ***
		// قبل از اینکه این کانکشن را فعال کنیم، هندشیک را اجرا می‌کنیم
		h.sendFakeHandshake(newConn)
		
		log.Printf("♻️ [Hopping] Handshake sent. Switching to Port: %d", newConn.localPort)

		// شروع خواندن از کانکشن جدید
		go h.readLoop(newConn)

		// سوییچ کردن کانکشن نوشتاری
		h.mu.Lock()
		oldConn := h.activeConn
		h.activeConn = newConn
		h.mu.Unlock()

		// نگه داشتن کانکشن قدیمی برای دریافت ACKهای جامانده (15 ثانیه)
		go func(old *RawTCPConn) {
			time.Sleep(15 * time.Second)
			old.Close()
		}(oldConn)
	}
}

func (h *HoppingPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case pkt := <-h.readCh:
		if pkt.Err != nil {
			return 0, nil, pkt.Err
		}
		copy(p, pkt.Data)
		return len(pkt.Data), pkt.Addr, nil
	}
}

func (h *HoppingPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	h.mu.RLock()
	conn := h.activeConn
	h.mu.RUnlock()
	return conn.WriteTo(p, addr)
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
//       RAW SOCKET IMPLEMENTATION
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
	conn.SetReadBuffer(16 * 1024 * 1024)
	conn.SetWriteBuffer(16 * 1024 * 1024)

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
	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)

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

		// بررسی فلگ‌ها: ما فقط دیتای PSH/ACK را می‌خواهیم
		// اگر سرور (کرنل) در جواب SYN ما چیزی فرستاد، اینجا نادیده می‌گیریم
		flags := buf[13]
		if flags&0x02 != 0 { // SYN packet received? Ignore.
			continue
		}

		copy(p, buf[20:n])

		fakeUDPAddr := &net.UDPAddr{
			IP:   src.(*net.IPAddr).IP,
			Port: int(packetSrcPort),
		}

		return n - 20, fakeUDPAddr, nil
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

	// 0x18 = PSH | ACK (دیتای نرمال)
	tcpHeader := MakeTCPHeaderCustom(c.localPort, dstPort, 0x18, p)
	packet := append(tcpHeader, p...)

	_, err = c.conn.WriteToIP(packet, &net.IPAddr{IP: dstIP})
	return len(p), err
}

// تابع ساخت هدر با قابلیت تعیین فلگ‌ها
func MakeTCPHeaderCustom(srcPort, dstPort int, flags byte, payload []byte) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(h[2:4], uint16(dstPort))
	// Seq and Ack numbers - Random is fine for FakeTCP usually
	binary.BigEndian.PutUint32(h[4:8], rand.Uint32())
	binary.BigEndian.PutUint32(h[8:12], rand.Uint32())
	
	h[12] = 0x50 // Header Length
	h[13] = flags // Control Flags (SYN, ACK, PSH, etc)
	binary.BigEndian.PutUint16(h[14:16], 65535) // Window Size
	
	// Checksum (Simplified: often redundant if OS does NIC offloading, but good to have zeroed)
	// We skip strict checksum calc for performance as GFW often ignores it for simple TCP checks
	
	return h
}

func (c *RawTCPConn) Close() error                       { return c.conn.Close() }
func (c *RawTCPConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: c.localPort} }
func (c *RawTCPConn) SetDeadline(t time.Time) error      { return nil }
func (c *RawTCPConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *RawTCPConn) SetWriteDeadline(t time.Time) error { return nil }