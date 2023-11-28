// Command leproxy implements https reverse proxy with automatic LetsEncrypt
// usage for multiple hostnames/backends, and URL rewriting capability.
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	stdLog "log"
	"mleku.online/git/lerproxy/buf"
	"mleku.online/git/lerproxy/tcpkeepalive"
	"mleku.online/git/lerproxy/util"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sync/errgroup"
	"mleku.online/git/autoflags"
	"mleku.online/git/lerproxy/hsts"
	log2 "mleku.online/git/log"
)

type runArgs struct {
	addr  string        `flag:"addr,address to listen at"`
	conf  string        `flag:"map,file with host/backend mapping"`
	cache string        `flag:"cacheDir,path to directory to cache key and certificates"`
	hsts  bool          `flag:"hsts,add Strict-Transport-Security header"`
	email string        `flag:"email,contact email address presented to letsencrypt CA"`
	http  string        `flag:"http,optional address to serve http-to-https redirects and ACME http-01 challenge responses"`
	rto   time.Duration `flag:"rto,maximum duration before timing out read of the request"`
	wto   time.Duration `flag:"wto,maximum duration before timing out write of the response"`
	idle  time.Duration `flag:"idle,how long idle connection is kept before closing (set rto, wto to 0 to use this)"`
}

var (
	log   = log2.GetLogger()
	fails = log.E.Chk
)

func main() {
	args := runArgs{
		addr:  ":https",
		http:  ":http",
		conf:  "mapping.txt",
		cache: "/var/cache/letsencrypt",
		rto:   time.Minute,
		wto:   5 * time.Minute,
	}
	autoflags.Parse(&args)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := run(ctx, args); err != nil {
		log.F.Ln(err)
	}
}

func run(ctx context.Context, args runArgs) (err error) {

	if args.cache == "" {
		return fmt.Errorf("no cache specified")
	}

	var srv *http.Server
	var httpHandler http.Handler
	srv, httpHandler, err = setupServer(args)
	if err != nil {
		return err
	}
	srv.ReadHeaderTimeout = 5 * time.Second
	if args.rto > 0 {
		srv.ReadTimeout = args.rto
	}
	if args.wto > 0 {
		srv.WriteTimeout = args.wto
	}
	group, ctx := errgroup.WithContext(ctx)
	if args.http != "" {
		httpServer := http.Server{
			Addr:         args.http,
			Handler:      httpHandler,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}
		group.Go(func() error { return httpServer.ListenAndServe() })
		group.Go(func() error {
			<-ctx.Done()
			ctx, cancel := context.WithTimeout(context.Background(),
				time.Second)
			defer cancel()
			return httpServer.Shutdown(ctx)
		})
	}
	if srv.ReadTimeout != 0 || srv.WriteTimeout != 0 || args.idle == 0 {
		group.Go(func() error { return srv.ListenAndServeTLS("", "") })
	} else {
		group.Go(func() error {
			ln, err := net.Listen("tcp", srv.Addr)
			if err != nil {
				return err
			}
			defer ln.Close()
			ln = tcpkeepalive.Listener{
				Duration:    args.idle,
				TCPListener: ln.(*net.TCPListener),
			}
			return srv.ServeTLS(ln, "", "")
		})
	}
	group.Go(func() error {
		<-ctx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	})
	return group.Wait()
}

func setupServer(a runArgs) (s *http.Server, h http.Handler, e error) {
	mapping, err := readMapping(a.conf)
	if err != nil {
		return nil, nil, err
	}
	proxy, err := setProxy(mapping)
	if err != nil {
		return nil, nil, err
	}
	if a.hsts {
		proxy = &hsts.Proxy{Handler: proxy}
	}
	if err := os.MkdirAll(a.cache, 0700); err != nil {
		return nil, nil, fmt.Errorf("cannot create cache directory %q: %v",
			a.cache, err)
	}
	m := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(a.cache),
		HostPolicy: autocert.HostWhitelist(util.GetKeys(mapping)...),
		Email:      a.email,
	}
	srv := &http.Server{
		Handler:   proxy,
		Addr:      a.addr,
		TLSConfig: m.TLSConfig(),
	}
	return srv, m.HTTPHandler(nil), nil
}

func setProxy(mapping map[string]string) (http.Handler, error) {
	if len(mapping) == 0 {
		return nil, fmt.Errorf("empty mapping")
	}
	mux := http.NewServeMux()
	for hostname, backendAddr := range mapping {
		hostname, backendAddr := hostname, backendAddr // intentional shadowing
		if strings.ContainsRune(hostname, os.PathSeparator) {
			return nil, fmt.Errorf("invalid hostname: %q", hostname)
		}
		network := "tcp"
		if backendAddr != "" && backendAddr[0] == '@' && runtime.GOOS == "linux" {
			// append \0 to address so addrlen for connect(2) is calculated in a
			// way compatible with some other implementations (i.e. uwsgi)
			network, backendAddr = "unix", backendAddr+string(byte(0))
		} else if filepath.IsAbs(backendAddr) {
			network = "unix"
			if strings.HasSuffix(backendAddr, string(os.PathSeparator)) {
				// path specified as directory with explicit trailing slash; add
				// this path as static site
				mux.Handle(hostname+"/", http.FileServer(http.Dir(backendAddr)))
				continue
			}
		} else if u, err := url.Parse(backendAddr); err == nil {
			switch u.Scheme {
			case "http", "https":
				rp := newSingleHostReverseProxy(u)
				rp.ErrorLog = stdLog.New(io.Discard, "", 0)
				rp.BufferPool = buf.Pool{}
				mux.Handle(hostname+"/", rp)
				continue
			}
		}
		rp := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = "http"
				req.URL.Host = req.Host
				req.Header.Set("X-Forwarded-Proto", "https")
			},
			Transport: &http.Transport{
				Dial: func(netw, addr string) (net.Conn, error) {
					return net.DialTimeout(network, backendAddr, 5*time.Second)
				},
			},
			ErrorLog:   stdLog.New(io.Discard, "", 0),
			BufferPool: buf.Pool{},
		}
		mux.Handle(hostname+"/", rp)
	}
	return mux, nil
}

func readMapping(file string) (map[string]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if b := sc.Bytes(); len(b) == 0 || b[0] == '#' {
			continue
		}
		s := strings.SplitN(sc.Text(), ":", 2)
		if len(s) != 2 {
			return nil, fmt.Errorf("invalid line: %q", sc.Text())
		}
		m[strings.TrimSpace(s[0])] = strings.TrimSpace(s[1])
	}
	return m, sc.Err()
}

// newSingleHostReverseProxy is a copy of httputil.NewSingleHostReverseProxy
// with addition of "X-Forwarded-Proto" header.
func newSingleHostReverseProxy(target *url.URL) *httputil.ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = util.SingleJoiningSlash(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
		req.Header.Set("X-Forwarded-Proto", "https")
	}
	return &httputil.ReverseProxy{Director: director}
}
