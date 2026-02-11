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
	salt          = "raw-tcp-tunnel-optimized-v5-final"
	dataShards    = 10
	parityShards  = 0    // برای حداکثر سرعت (اگر پکت‌لاس زیاد دارید 1 کنید)
	mtuLimit      = 1350 
	headerSize    = 20   
	checkInterval = 5 * time.Second
)

var (
	lastPacketTime int64
	
	// بافر 32 کیلوبایتی برای انتقال داده‌ها
	bufPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 32*1024)
			return &b
		},
	}
	
	// بافر برای بسته‌های Raw (هدر + MTU)
	packetPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, mtuLimit+headerSize)
			return b // اینجا خود Slice را برمی‌گردانیم نه پوینتر، برای راحتی در WriteTo
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

	// Seed فقط برای پورت کلاینت استفاده می‌شود، نه کریپتو
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
	log.Printf("🚀 [SERVER] Starting Final Optimized Tunnel on Port %d", port)

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
		conn.SetWindowSize(1024, 1024) 
		conn.SetNoDelay(1, 10, 2, 1)
		conn.SetMtu(mtuLimit)
		conn.SetACKNoDelay(true)

		smuxConf := smux.DefaultConfig()
		smuxConf.KeepAliveInterval = 10 * time.Second
		smuxConf.KeepAliveTimeout = 45 * time.Second
		smuxConf.MaxFrameSize = 32768
		// بافر ریسیو را کمی محدود کردیم تا در تعداد کاربر بالا رم منفجر نشود
		smuxConf.MaxReceiveBuffer = 2 * 1024 * 1024 

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
			
			// هندل کردن درخواست SOCKS/Forwarding به صورت دستی برای جلوگیری از سربار اضافی
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
	kcpSess.SetWindowSize(4096, 4096) // کلاینت می‌تواند بافر بزرگتری داشته باشد
	kcpSess.SetNoDelay(1, 10, 2, 1)
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

	// WATCHDOG
	go func() {
		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()
		for range ticker.C {
			if session.IsClosed() {
				log.Println("🔴 [RESTART] Session closed.")
				os.Exit(1)
			}
			last := atomic.LoadInt64(&lastPacketTime)
			if time.Now().Unix()-last > 25 {
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

// Pipe بهینه شده با استفاده صحیح از sync.Pool
func pipe(c1, c2 io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		bufPtr := bufPool.Get().(*[]byte)
		defer bufPool.Put(bufPtr)
		io.CopyBuffer(c1, c2, *bufPtr)
		c1.Close()
		c2.Close()
	}()

	go func() {
		defer wg.Done()
		bufPtr := bufPool.Get().(*[]byte)
		defer bufPool.Put(bufPtr)
		io.CopyBuffer(c2, c1, *bufPtr)
		c2.Close()
		c1.Close()
	}()

	wg.Wait()
}

// ==========================================
//              OPTIMIZED RAW SOCKET
// ==========================================

type RawTCPConn struct {
	pConn      *ipv4.PacketConn
	localPort  int
	remotePort int
	remoteIP   net.IP
	mode       string
	seq        uint32
}

func NewRawTCPConn(localPort, remotePort int, mode, remoteIPStr string) (*RawTCPConn, error) {
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	pConn := ipv4.NewPacketConn(conn)

	// BPF Filter: فقط بسته‌های مربوط به پورت ما را از کرنل بگیر
	filter, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 9, Size: 1}, // Protocol
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 6, SkipTrue: 10}, 
		bpf.LoadAbsolute{Off: 6, Size: 2}, // Fragment
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 8},
		bpf.LoadAbsolute{Off: 22, Size: 2}, // DstPort
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(localPort), SkipTrue: 4},
		bpf.RetConstant{Val: 0xFFFF},
		bpf.RetConstant{Val: 0},
	})

	if err == nil {
		pConn.SetBPF(filter)
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
	// استفاده صحیح از Pool برای خواندن پکت
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	for {
		n, _, src, err := c.pConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}

		if n < 40 { continue } // حداقل سایز IP+TCP

		// Parse TCP Header
		// فرض بر این است که هدر IP استاندارد (20 بایت) است.
		tcpHeader := buf[20:] 
		packetDstPort := binary.BigEndian.Uint16(tcpHeader[2:4])

		if int(packetDstPort) != c.localPort {
			continue
		}

		atomic.StoreInt64(&lastPacketTime, time.Now().Unix())

		dataOffset := (tcpHeader[12] >> 4) * 4
		if int(dataOffset) > n-20 { continue }

		payload := tcpHeader[dataOffset:]
		if len(payload) == 0 { continue }

		copy(p, payload)
		// تبدیل آدرس IP به UDPAddr برای KCP
		packetSrcPort := binary.BigEndian.Uint16(tcpHeader[0:2])
		return len(payload), &net.UDPAddr{IP: src.(*net.IPAddr).IP, Port: int(packetSrcPort)}, nil
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

	// استفاده از packetPool (نوع []byte نه pointer)
	pkt := packetPool.Get().([]byte)
	defer packetPool.Put(pkt)
	
	// TCP Header Generation
	binary.BigEndian.PutUint16(pkt[0:2], uint16(c.localPort))
	binary.BigEndian.PutUint16(pkt[2:4], uint16(dstPort))
	
	// Atomic Sequence (بدون قفل)
	newSeq := atomic.AddUint32(&c.seq, 1)
	binary.BigEndian.PutUint32(pkt[4:8], newSeq)
	binary.BigEndian.PutUint32(pkt[8:12], 0)
	pkt[12], pkt[13] = 0x50, 0x18 // DataOffset=5, Flags=ACK+PSH
	pkt[14], pkt[15] = 0xFF, 0xFF // Window
	pkt[16], pkt[17] = 0, 0       // Checksum (Zero for performance)
	pkt[18], pkt[19] = 0, 0       // Urgent

	copy(pkt[20:], p)
	totalLen := 20 + len(p)

	_, err = c.pConn.WriteTo(pkt[:totalLen], nil, &net.IPAddr{IP: dstIP})
	return len(p), err
}

func (c *RawTCPConn) Close() error                       { return c.pConn.Close() }
func (c *RawTCPConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: c.localPort} }
func (c *RawTCPConn) SetDeadline(t time.Time) error      { return c.pConn.SetDeadline(t) }
func (c *RawTCPConn) SetReadDeadline(t time.Time) error  { return c.pConn.SetReadDeadline(t) }
func (c *RawTCPConn) SetWriteDeadline(t time.Time) error { return c.pConn.SetWriteDeadline(t) }