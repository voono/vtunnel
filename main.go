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
)

const (
	salt         = "raw-tcp-tunnel-watchdog-v3"
	dataShards   = 10
	parityShards = 3
	mtuLimit     = 1100 // کاهش به 1100 برای عبور راحت‌تر
	
	// اگر ۴۵ ثانیه دیتایی نیامد، یعنی فیلتر شده‌ایم -> ریستارت
	readTimeout  = 45 * time.Second 
)

// متغیر اتمی برای ذخیره زمان آخرین فعالیت
var lastActivity int64

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

	// آپدیت زمان شروع
	updateActivity()

	pass := pbkdf2.Key([]byte(*key), []byte(salt), 4096, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(pass)

	if *mode == "server" {
		runServer(*port, block)
	} else {
		if *remote == "" {
			log.Fatal("Client mode requires -remote <IP>")
		}
		// اجرای Watchdog فقط در کلاینت
		go startWatchdog()
		runClient(*listen, *fwd, *remote, *port, block)
	}
}

// این تابع هر ۵ ثانیه چک می‌کند که آیا ترافیک داریم یا نه
// اگر ترافیک قطع شده بود، برنامه را می‌بندد تا با پورت جدید باز شود
func startWatchdog() {
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		last := atomic.LoadInt64(&lastActivity)
		lastTime := time.Unix(last, 0)
		
		if time.Since(lastTime) > readTimeout {
			log.Printf("❌ [Watchdog] No traffic for %v. Promoting Restart for Port Hopping...", time.Since(lastTime))
			os.Exit(1) // خروج با ارور تا systemd ریستارت کند
		}
	}
}

func updateActivity() {
	atomic.StoreInt64(&lastActivity, time.Now().Unix())
}

// ==========================================
//              SERVER LOGIC
// ==========================================

func runServer(port int, block kcp.BlockCrypt) {
	log.Printf("🚀 [Server] Stable Tunnel starting on Port %d...", port)

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
		
		// KCP KeepAlive
		conn.SetReadDeadline(time.Now().Add(3 * time.Minute))

		smuxConf := smux.DefaultConfig()
		smuxConf.KeepAliveInterval = 5 * time.Second // چک کردن زنده بودن لینک هر ۵ ثانیه
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
			
			// تمدید ددلاین در سمت سرور
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
	// انتخاب پورت رندوم برای هر بار اجرا
	localSrcPort := rand.Intn(15000) + 40000 
	log.Printf("🚀 [Client] Connecting via Source Port %d...", localSrcPort)

	rawConn, err := NewRawTCPConn(localSrcPort, remotePort, "client", remoteIP)
	if err != nil {
		log.Fatalf("Socket Error: %v", err)
	}

	kcpSess, err := kcp.NewConn(fmt.Sprintf("%s:%d", remoteIP, remotePort), block, dataShards, parityShards, rawConn)
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

	// KeepAlive سریع برای اینکه اگر پکت لاس شد سریع بفهمیم
	smuxConf := smux.DefaultConfig()
	smuxConf.KeepAliveInterval = 5 * time.Second 
	smuxConf.KeepAliveTimeout = 15 * time.Second

	session, err := smux.Client(kcpSess, smuxConf)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	// مانیتورینگ وضعیت سشن Smux
	go func() {
		for {
			time.Sleep(2 * time.Second)
			if session.IsClosed() {
				log.Println("Session Closed by Smux -> Exiting")
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
			
			// هر دیتایی که رد و بدل شود، یعنی زنده هستیم
			updateActivity() 

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

	go func() {
		defer wg.Done()
		copyLoop(c1, c2)
		c1.Close()
	}()

	go func() {
		defer wg.Done()
		copyLoop(c2, c1)
		c2.Close()
	}()

	wg.Wait()
}

func copyLoop(src io.Reader, dst io.Writer) {
	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)

	for {
		nr, err := src.Read(buf)
		if nr > 0 {
			// ** مهم: آپدیت فعالیت با هر بار خواندن دیتا **
			updateActivity()
			
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				break
			}
			if ew != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
}

// ==========================================
//       RAW SOCKET 
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
		// ددلاین برای خواندن از سوکت خام، تا اگر دیتا نیامد لوپ گیر نکند
		c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, src, err := c.conn.ReadFrom(buf)
		
		if err != nil {
			// اگر تایم اوت شد، فقط لوپ را ادامه بده تا واچ‌داگ چک کند
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return 0, nil, err
			}
			return 0, nil, err
		}
		
		if n <= 20 {
			continue
		}
		
		// با هر پکت دریافتی هم اکتیویتی را آپدیت کن
		updateActivity()

		packetDstPort := binary.BigEndian.Uint16(buf[2:4])
		packetSrcPort := binary.BigEndian.Uint16(buf[0:2])

		if int(packetDstPort) != c.localPort {
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

	tcpHeader := MakeTCPHeader(c.localPort, dstPort, p)
	packet := append(tcpHeader, p...)

	_, err = c.conn.WriteToIP(packet, &net.IPAddr{IP: dstIP})
	return len(p), err
}

func MakeTCPHeader(srcPort, dstPort int, payload []byte) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(h[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(h[4:8], rand.Uint32())
	binary.BigEndian.PutUint32(h[8:12], rand.Uint32())
	h[12] = 0x50 
	h[13] = 0x18 
	binary.BigEndian.PutUint16(h[14:16], 65535) 
	return h
}

func (c *RawTCPConn) Close() error                       { return c.conn.Close() }
func (c *RawTCPConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: c.localPort} }
func (c *RawTCPConn) SetDeadline(t time.Time) error      { return nil }
func (c *RawTCPConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *RawTCPConn) SetWriteDeadline(t time.Time) error { return nil }