package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"sort"
	"sync"
	"syscall"
	"time"

	"gopkg.in/fsnotify.v1"
	"gopkg.in/yaml.v3"
)

// const useTLS = false

const demoVer = "3.1.2"

var (
	appUser string
	allDone bool
	hostIps map[string][]string
)

const (
	cfgFile = "./config/config-nic-demo.json"
	// srvrCert              = "./certs/srvrcert-nic-demo.pem"
	// srvrKey               = "./certs/srvrKey-nic-demo.pem"
	KubeTLSSecretLocation = "./certs/"
	KubeCertLocation      = KubeTLSSecretLocation + "tls.crt"
	KubeKeyLocation       = KubeTLSSecretLocation + "tls.key"
	KubeCaCertLocation    = "./cacert/caCert.pem"
)

type config struct {
	UseTLS    bool     `json:"usetls"`
	UseMTLS   bool     `json:"usemtls"`
	ValueA    string   `json:"valuea"`
	ValueB    int      `json:"valueb"`
	HostNames []string `json:"hostNames"`
}

func main() {
	fmt.Printf("This is nic-demo version: %s\n", demoVer)
	usr, err := getUser()
	if err != nil {
		fmt.Printf("determining user: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("(Running as user %q)\n", usr)
	appUser = usr

	cfg, err := loadJsonConfig(cfgFile)
	if err != nil {
		fmt.Printf("loading application config: %v\n", err)
		os.Exit(1)
	}
	tlsCfg, err := loadKubeTLS(cfg.UseTLS, cfg.UseMTLS)
	if err != nil {
		fmt.Printf("loading TLS config: %v\n", err)
		os.Exit(1)
	}
	hostIps = make(map[string][]string)
	go lookupAll(cfg.HostNames)
	srvr := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  time.Minute * 5,
		WriteTimeout: time.Second * 10,
		TLSConfig:    tlsCfg,
	}
	http.HandleFunc("/", handler)
	if cfg.UseTLS {
		fmt.Println("staring server using TLS, listening on 8080")
		srvr.ListenAndServeTLS(KubeCertLocation, KubeKeyLocation)
	} else {
		fmt.Println("starting server without TLS, listening on 8080")
		srvr.ListenAndServe()
	}
}

func loadJsonConfig(configFile string) (*config, error) {
	conf := config{}
	configData, err := os.ReadFile(configFile)
	if err != nil {
		fmt.Printf("loadJsonConfig: loading config file %s: %v", configFile, err)
		return nil, err
	}
	err = json.Unmarshal(configData, &conf)
	if err != nil {
		fmt.Printf("loadJsonConfig: unmarshaling file %s: %v", configFile, err)
		return nil, err
	}
	fmt.Println("======== CONFIG 1 =======")
	fmt.Printf("%+v\n", conf)
	fmt.Println("=======================")
	fmt.Println("======== CONFIG 2 =======")
	fmt.Printf("%#v\n", conf)
	fmt.Println("=======================")
	return &conf, nil
}

// https://www.usenix.org/sites/default/files/conference/protected-files/srecon20americas_slides_hahn.pdf
func loadKubeTLS(useTls, useMtls bool) (*tls.Config, error) {
	if !useTls {
		return &tls.Config{}, nil
	}
	cert, err := tls.LoadX509KeyPair(KubeCertLocation, KubeKeyLocation)
	if err != nil {
		return nil, fmt.Errorf("NewKubeTLS: loading TLS cert and key: %w", err)
	}
	caCertPem, err := getCaCert()
	if err != nil {
		return nil, fmt.Errorf("NewKubeTLS: getting CA cert")
	}
	srvrPool := x509.NewCertPool()
	if !srvrPool.AppendCertsFromPEM(caCertPem) {
		return nil, fmt.Errorf("NewKubeTLS: failed adding CA cert to pool")
	}
	tc := tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
		ClientCAs:    srvrPool,
		RootCAs:      srvrPool,
	}
	if useMtls {
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return &tc, nil
}

func getCaCert() ([]byte, error) {
	return os.ReadFile(KubeCertLocation)
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(fmt.Sprintf("<h2>NIC Demo application, ver: %s</h2><div>I'm running as user %q</div>", demoVer, appUser)))
	if !allDone {
		w.Write([]byte("<p>I'm still doing lookup, please reload...</p>"))
		return
	}
	keys := make([]string, len(hostIps))
	i := 0
	for k := range hostIps {
		keys[i] = k
		i++
	}
	sort.Strings(keys)
	for _, hn := range keys {
		w.Write([]byte(fmt.Sprintf("<b>%s</b>: %v<br>\n", hn, hostIps[hn])))
	}
}

func getUser() (string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", err
	}
	return currentUser.Username, nil
}

func lookupAll(names []string) {
	for _, nm := range names {
		ips, err := lookupHostName(nm)
		if err != nil {
			hostIps[nm] = []string{err.Error()}
			continue
		}
		hostIps[nm] = ips
	}
	allDone = true
}

func lookupHostName(name string) ([]string, error) {
	var res []string
	ips, err := net.LookupIP(name)
	if err != nil {
		return res, err
	}
	for _, ip := range ips {
		res = append(res, ip.String())
	}
	return res, nil
}

// =========================================================

func checkFileExists(fn string) {
	if _, err := os.Stat(fn); err != nil {
		fmt.Printf("file \"%s\" does NOT exist: %v\n", fn, err)
	} else {
		fmt.Printf("file \"%s\" DOES exist\n", fn)
	}

	files, err := os.ReadDir("./certs")
	fmt.Printf("looking in %s:\n", "./certs")
	if err != nil {
		fmt.Printf("reading dir: %v\n", err)
	}

	for _, file := range files {
		fmt.Println(file.Name(), file.IsDir())
	}

	files, err = os.ReadDir(KubeTLSSecretLocation)
	fmt.Printf("looking in %s:\n", KubeTLSSecretLocation)
	if err != nil {
		fmt.Printf("reading dir: %v\n", err)
	}

	for _, file := range files {
		fmt.Println(file.Name(), file.IsDir())
	}
}

func main_old3() {
	fmt.Printf("This is nic-demo version: %s\n", demoVer)

	for _, fn := range []string{cfgFile, KubeCaCertLocation, KubeCertLocation, KubeKeyLocation} {
		checkFileExists(fn)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigs
	fmt.Println("Application terminated ", sig)
}

func main_old() {
	fmt.Printf("This is nic-demo version: %s", demoVer)
	cfg, err := loadConfig(cfgFile)
	if err != nil {
		fmt.Printf("loading config: %v", err)
	}
	confManager := NewMutexConfigManager(cfg)

	conf := confManager.Get()
	fmt.Printf("Config:\n\t%s\n\t%d\n", conf.ValueA, conf.ValueB)

	watcher, err := WatchFile(cfgFile, time.Second, func() {
		fmt.Println("Config file updated")
		conf, err = loadConfig(cfgFile)
		if err != nil {
			fmt.Printf("loading config: %v", err)
			confManager.Set(conf)
		}
		conf := confManager.Get()
		fmt.Printf("Config (new):\n\t%s\n\t%d\n", conf.ValueA, conf.ValueB)
	})
	if err != nil {
		fmt.Printf("watching file: %v", err)
	}

	defer func() {
		watcher.Close()
		confManager.Close()
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigs
	fmt.Println("Application terminated ", sig)
}

func loadConfig(configFile string) (*config, error) {
	conf := config{}
	configData, err := os.ReadFile(configFile)
	if err != nil {
		fmt.Printf("loading config file %s: %v", configFile, err)
		return nil, err
	}

	err = yaml.Unmarshal(configData, &conf)
	if err != nil {
		fmt.Printf("unmarshaling file %s: %v", configFile, err)
		return nil, err
	}
	return &conf, nil
}

type ConfigManager interface {
	Set(*config)
	Get() *config
	Close()
}

type MutexConfigManager struct {
	conf  *config
	mutex *sync.Mutex
}

func NewMutexConfigManager(cfg *config) *MutexConfigManager {
	return &MutexConfigManager{
		conf:  cfg,
		mutex: &sync.Mutex{},
	}
}

func (mcm *MutexConfigManager) Set(cfg *config) {
	mcm.mutex.Lock()
	mcm.conf = cfg
	mcm.mutex.Unlock()
}

func (mcm *MutexConfigManager) Get() *config {
	mcm.mutex.Lock()
	tmp := mcm.conf
	mcm.mutex.Unlock()
	return tmp
}

func (mcm *MutexConfigManager) Close() {
}

type FileWatcher struct {
	fsNotify *fsnotify.Watcher
	interval time.Duration
	done     chan struct{}
	callback func()
}

func WatchFile(path string, interval time.Duration, action func()) (*FileWatcher, error) {
	fsWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	fsWatcher.Add(path)
	watcher := &FileWatcher{
		fsNotify: fsWatcher,
		interval: interval,
		done:     make(chan struct{}, 1),
		callback: action,
	}
	go watcher.run()
	return watcher, err
}

func (fw *FileWatcher) run() {
	tick := time.Tick(fw.interval)
	var lastWriteEvent *fsnotify.Event
	for {
		select {
		case event := <-fw.fsNotify.Events:
			if event.Op == fsnotify.Remove {
				fw.fsNotify.Remove(event.Name)
				fw.fsNotify.Add(event.Name)
				lastWriteEvent = &event
			}
			if event.Op == fsnotify.Write {
				lastWriteEvent = &event
			}
		case <-tick:
			if lastWriteEvent == nil {
				continue
			}
			fw.callback()
			lastWriteEvent = nil
		case <-fw.done:
			goto Close
		}
	}
Close:
	close(fw.done)
}

func (fw *FileWatcher) Close() {
	fw.done <- struct{}{}
	fw.fsNotify.Close()
}

// ==================================== OLD EXAMPLE ====================================
/*
func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(fmt.Sprintf("<h2>Ver: %s</h2>", demoVer)))
	// fmt.Fprintf(w, "This is an example server.\n")
	// io.WriteString(w, "This is an example server.\n")
}

func main_old() {
	http.HandleFunc("/", handler)
	if useTLS {
		http.ListenAndServeTLS(":8080", "/certs/demo_srvr_cert.pem", "/certs/demo_server_key.pem", nil)
	} else {
		http.ListenAndServe(":8080", nil)
	}
}
*/
