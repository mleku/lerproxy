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
	Addr  string        `flag:"addr,address to listen at"`
	Conf  string        `flag:"map,file with host/backend mapping"`
	Cache string        `flag:"cacheDir,path to directory to cache key and certificates"`
	HSTS  bool          `flag:"hsts,add Strict-Transport-Security header"`
	Email string        `flag:"email,contact email address presented to letsencrypt CA"`
	HTTP  string        `flag:"http,optional address to serve http-to-https redirects and ACME http-01 challenge responses"`
	RTO   time.Duration `flag:"rto,maximum duration before timing out read of the request"`
	WTO   time.Duration `flag:"wto,maximum duration before timing out write of the response"`
	Idle  time.Duration `flag:"idle,how long idle connection is kept before closing (set rto, wto to 0 to use this)"`
}

var (
	log   = log2.GetLogger()
	fails = log.E.Chk
)

func main() {
	args := runArgs{
		Addr:  ":https",
		HTTP:  ":http",
		Conf:  "mapping.txt",
		Cache: "/var/cache/letsencrypt",
		RTO:   time.Minute,
		WTO:   5 * time.Minute,
	}
	autoflags.Parse(&args)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := run(ctx, args); err != nil {
		log.F.Ln(err)
	}
}

func run(ctx context.Context, args runArgs) (err error) {

	if args.Cache == "" {
		return fmt.Errorf("no cache specified")
	}

	var srv *http.Server
	var httpHandler http.Handler
	srv, httpHandler, err = setupServer(args)
	if err != nil {
		return err
	}
	srv.ReadHeaderTimeout = 5 * time.Second
	if args.RTO > 0 {
		srv.ReadTimeout = args.RTO
	}
	if args.WTO > 0 {
		srv.WriteTimeout = args.WTO
	}
	group, ctx := errgroup.WithContext(ctx)
	if args.HTTP != "" {
		httpServer := http.Server{
			Addr:         args.HTTP,
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
	if srv.ReadTimeout != 0 || srv.WriteTimeout != 0 || args.Idle == 0 {
		group.Go(func() error { return srv.ListenAndServeTLS("", "") })
	} else {
		group.Go(func() error {
			ln, err := net.Listen("tcp", srv.Addr)
			if err != nil {
				return err
			}
			defer ln.Close()
			ln = tcpkeepalive.Listener{
				Duration:    args.Idle,
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
	mapping, err := readMapping(a.Conf)
	if err != nil {
		return nil, nil, err
	}
	proxy, err := setProxy(mapping)
	if err != nil {
		return nil, nil, err
	}
	if a.HSTS {
		proxy = &hsts.Proxy{Handler: proxy}
	}
	if err := os.MkdirAll(a.Cache, 0700); err != nil {
		return nil, nil, fmt.Errorf("cannot create cache directory %q: %v",
			a.Cache, err)
	}
	m := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(a.Cache),
		HostPolicy: autocert.HostWhitelist(util.GetKeys(mapping)...),
		Email:      a.Email,
	}
	srv := &http.Server{
		Handler:   proxy,
		Addr:      a.Addr,
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
