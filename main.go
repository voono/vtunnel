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
	"sync/atomic"
	"time"

	"github.com/armon/go-socks5"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

const (
	salt          = "raw-tcp-tunnel-optimized-v4"
	dataShards    = 10
	parityShards  = 0    // بهینه‌سازی: کاهش سربار FEC به 10%
	mtuLimit      = 1350 // افزایش MTU برای بهره‌وری بیشتر (با احتساب هدر)
	headerSize    = 20   // TCP Header size
	idleTimeout   = 60 * time.Second
	checkInterval = 5 * time.Second
)

var (
	lastPacketTime int64
	// استفاده از بافر بزرگتر برای انتقال سریع‌تر
	bufPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 32*1024)
			return &b
		},
	}
	// استخر مخصوص پکت‌های خروجی برای جلوگیری از Allocation
	packetPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, mtuLimit+headerSize)
		},
	}
)

func main() {
	mode := flag.String("mode", "server", "Mode: 'server' or 'client'")
	listen := flag.String("listen", "", "SOCKS5 Listen Address")
	fwd := flag.String("fwd", "", "Port Forwarding rule")
	remote := flag.String("remote", "", "Server IP")
	port := flag.Int("port", 443, "Tunnel Port")
	key := flag.String("key", "secret", "Encryption key")
	flag.Parse()

	rand.Seed(time.Now().UnixNano())
	atomic.StoreInt64(&lastPacketTime, time.Now().Unix())

	pass := pbkdf2.Key([]byte(*key), []byte(salt), 4096, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(pass)

	if *mode == "server" {
		runServer(*port, block)
	} else {
		if *remote == "" {
			log.Fatal("❌ Client mode requires -remote <IP>")
		}
		runClient(*listen, *fwd, *remote, *port, block)
	}
}

// ==========================================
//              SERVER LOGIC
// ==========================================

func runServer(port int, block kcp.BlockCrypt) {
	log.Printf("🚀 [SERVER] Starting Optimized Raw Tunnel on Port %d", port)

	// اتصال به Raw Socket با فیلتر BPF
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

		// تنظیمات KCP برای حداکثر سرعت
		conn := sess.(*kcp.UDPSession)
		conn.SetStreamMode(true)
		conn.SetWindowSize(1024, 1024)
		conn.SetNoDelay(1, 10, 2, 1)   // Interval 10ms
		conn.SetMtu(mtuLimit)
		conn.SetACKNoDelay(true)

		smuxConf := smux.DefaultConfig()
		smuxConf.KeepAliveInterval = 10 * time.Second
		smuxConf.KeepAliveTimeout = 45 * time.Second
		smuxConf.MaxFrameSize = 32768 // فریم‌های بزرگتر برای CPU کمتر
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
			// حذف Deadline برای استریم‌های طولانی مگر اینکه داده نیاید
			// s.SetReadDeadline(time.Now().Add(idleTimeout))

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
	kcpSess.SetNoDelay(1, 10, 2, 1) // Interval 10ms, Resend 2
	kcpSess.SetMtu(mtuLimit)
	kcpSess.SetACKNoDelay(true)

	smuxConf := smux.DefaultConfig()
	smuxConf.KeepAliveInterval = 5 * time.Second
	smuxConf.KeepAliveTimeout = 20 * time.Second
	smuxConf.MaxFrameSize = 32768
	smuxConf.MaxReceiveBuffer = 4194304

	session, err := smux.Client(kcpSess, smuxConf)
	if err != nil {
		log.Printf("❌ Smux Error: %v", err)
		os.Exit(1)
	}

	// WATCHDOG بهینه شده
	go func() {
		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()
		for range ticker.C {
			if session.IsClosed() {
				log.Println("🔴 [RESTART] Session closed.")
				os.Exit(1)
			}
			last := atomic.LoadInt64(&lastPacketTime)
			if time.Now().Unix()-last > 20 { // 20 ثانیه بدون پکت
				log.Println("💀 [RESTART] Network Frozen (No RX).")
				rawConn.Close()
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
	go func() { defer wg.Done(); io.CopyBuffer(c1, c2, *bufPool.New().(*[]byte)); c1.Close(); c2.Close() }()
	go func() { defer wg.Done(); io.CopyBuffer(c2, c1, *bufPool.New().(*[]byte)); c2.Close(); c1.Close() }()
	wg.Wait()
}

// ==========================================
//              OPTIMIZED RAW SOCKET
// ==========================================

type RawTCPConn struct {
	pConn      *ipv4.PacketConn // استفاده از ipv4 packet conn برای BPF
	localPort  int
	remotePort int
	remoteIP   net.IP
	mode       string
	seq        uint32 // کانتر ساده برای Sequence
}

func NewRawTCPConn(localPort, remotePort int, mode, remoteIPStr string) (*RawTCPConn, error) {
	// باز کردن سوکت Raw
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	// تبدیل به ipv4.PacketConn برای اعمال BPF
	pConn := ipv4.NewPacketConn(conn)

	// --- BPF FILTERING (CRITICAL OPTIMIZATION) ---
	// این فیلتر به کرنل می‌گوید فقط بسته‌هایی که پورت مقصدشان
	// برابر با localPort است را به برنامه پاس بدهد.
	// توجه: این اسمبلی برای IPv4 استاندارد (بدون Options) است.
	filter, err := bpf.Assemble([]bpf.Instruction{
		// Load Protocol (Byte at offset 9)
		bpf.LoadAbsolute{Off: 9, Size: 1},
		// Jump if not TCP (Protocol 6) -> Drop
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 6, SkipTrue: 10}, 
		
		// Load Fragment Offset (Offset 6, 2 bytes)
		bpf.LoadAbsolute{Off: 6, Size: 2},
		// Mask out flags (0x1fff)
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 8},

		// Load IP Header Length (IHL) to find where Data starts
		// (Actually for raw socket we assume standard header or use relative loads, 
		// but simple raw sockets usually give IP header. Let's assume offset 22 for DstPort)
		
		// Load Destination Port (Offset 22 in IP header)
		bpf.LoadAbsolute{Off: 22, Size: 2},
		// Jump if not equal to localPort -> Drop
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(localPort), SkipTrue: 4},

		// Keep Packet (Return -1 aka 65535 bytes)
		bpf.RetConstant{Val: 0xFFFF},

		// Drop Packet (Return 0)
		bpf.RetConstant{Val: 0},
	})

	if err == nil {
		// اعمال فیلتر فقط در لینوکس کار می‌کند
		if err := pConn.SetBPF(filter); err != nil {
			log.Printf("⚠️ Warning: BPF not supported/failed: %v. CPU usage might be high.", err)
		} else {
			log.Println("✅ BPF Filter applied! (Kernel-level filtering enabled)")
		}
	} else {
		log.Printf("⚠️ BPF Assembly error: %v", err)
	}

	var rip net.IP
	if remoteIPStr != "" {
		rip = net.ParseIP(remoteIPStr)
	}

	return &RawTCPConn{
		pConn:      pConn,
		localPort:  localPort,
		remotePort: remotePort,
		remoteIP:   rip,
		mode:       mode,
		seq:        rand.Uint32(),
	}, nil
}

func (c *RawTCPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// بافر بزرگ برای خواندن از کرنل
	bufPtr := bufPool.New().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	for {
		// حذف SetReadDeadline از این حلقه برای جلوگیری از سربار Syscall
		// BPF فیلتر می‌کند، پس اکثر پکت‌ها معتبر هستند
		n, _, src, err := c.pConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}

		// پردازش هدر TCP
		// با فرض اینکه هدر IP وجود دارد (20 بایت اول)، هدر TCP بعد از آن است.
		// offset 20 = شروع هدر TCP
		if n < 40 { // 20 IP + 20 TCP
			continue 
		}

		tcpHeader := buf[20:] // پرش از روی هدر IP
		packetSrcPort := binary.BigEndian.Uint16(tcpHeader[0:2])
		packetDstPort := binary.BigEndian.Uint16(tcpHeader[2:4])

		// چک نهایی (اگر BPF کار نکرد یا پکت عجیب بود)
		if int(packetDstPort) != c.localPort {
			continue
		}

		// آپدیت زمان برای Watchdog
		atomic.StoreInt64(&lastPacketTime, time.Now().Unix())

		// محاسبه طول هدر TCP (Data Offset)
		dataOffset := (tcpHeader[12] >> 4) * 4
		if int(dataOffset) > n-20 {
			continue
		}

		payload := tcpHeader[dataOffset:]
		payloadLen := len(payload)

		if payloadLen == 0 {
			continue
		}

		copy(p, payload)
		// src در اینجا آدرس IP است (net.IPAddr)، باید به UDPAddr تبدیل کنیم برای KCP
		return payloadLen, &net.UDPAddr{IP: src.(*net.IPAddr).IP, Port: int(packetSrcPort)}, nil
	}
}

func (c *RawTCPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var dstIP net.IP
	var dstPort int
	
	if c.mode == "client" {
		dstIP, dstPort = c.remoteIP, c.remotePort
	} else {
		udp, ok := addr.(*net.UDPAddr)
		if !ok { return 0, net.ErrWriteToConnected }
		dstIP, dstPort = udp.IP, udp.Port
	}

	// استفاده از پکت پول برای جلوگیری از Allocation
	pkt := packetPool.Get().([]byte)
	// مطمئن شویم پکت به استخر برمی‌گردد (البته در این ساختار KCP کپی می‌کند و ما می‌فرستیم،
	// اما چون WriteTo بلاک می‌کند تا ارسال انجام شود، می‌توانیم اینجا Put کنیم؟
	// خیر، WriteToIP کپی می‌کند؟ بله safe است.)
	defer packetPool.Put(pkt)
	
	// ساخت هدر TCP در همان بافر
	// پورت مبدا
	binary.BigEndian.PutUint16(pkt[0:2], uint16(c.localPort))
	// پورت مقصد
	binary.BigEndian.PutUint16(pkt[2:4], uint16(dstPort))
	// Sequence Number (سریع)
	atomic.AddUint32(&c.seq, 1)
	binary.BigEndian.PutUint32(pkt[4:8], c.seq)
	// Ack Number
	binary.BigEndian.PutUint32(pkt[8:12], 0)
	// Data Offset (5 words = 20 bytes) & Flags (ACK + PSH = 0x18)
	pkt[12] = 0x50 
	pkt[13] = 0x18 
	// Window Size
	pkt[14], pkt[15] = 0xFF, 0xFF
	// Checksum (0 برای راحتی، کرنل معمولا پر نمی‌کند مگر raw باشد)
	pkt[16], pkt[17] = 0, 0
	// Urgent Pointer
	pkt[18], pkt[19] = 0, 0

	// کپی داده‌ها به بعد از هدر
	copy(pkt[20:], p)
	totalLen := 20 + len(p)

	// ارسال مستقیم
	_, err = c.pConn.WriteTo(pkt[:totalLen], nil, &net.IPAddr{IP: dstIP})
	return len(p), err
}

func (c *RawTCPConn) Close() error                       { return c.pConn.Close() }
func (c *RawTCPConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: c.localPort} }
func (c *RawTCPConn) SetDeadline(t time.Time) error      { return c.pConn.SetDeadline(t) }
func (c *RawTCPConn) SetReadDeadline(t time.Time) error  { return c.pConn.SetReadDeadline(t) }
func (c *RawTCPConn) SetWriteDeadline(t time.Time) error { return c.pConn.SetWriteDeadline(t) }