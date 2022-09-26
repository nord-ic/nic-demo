package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"gopkg.in/fsnotify.v1"
	"gopkg.in/yaml.v3"
)

// const useTLS = false

const demoVer = "2.0.6"

const (
	cfgFile               = "./config/config-nic-demo.json"
	srvrCert              = "./config/srvrcert-nic-demo.pem"
	srvrKey               = "./config/srvrKey-nic-demo.pem"
	KubeTLSSecretLocation = "./config/srvrcert-nic-demo/"
	KubeCertLocation      = KubeTLSSecretLocation + "tls.crt"
	KubeKeyLocation       = KubeTLSSecretLocation + "tls.key"
	KubeCALocation        = KubeTLSSecretLocation + "ca.crt"
)

type config struct {
	UseTLS  bool   `json:"useTls"`
	UseMTLS bool   `json:"useMTls"`
	ValueA  string `json:"valuea"`
	ValueB  int    `json:"valueb"`
}

func main() {
	fmt.Printf("This is nic-demo version: %s", demoVer)
	cfg, err := loadJsonConfig(cfgFile)
	if err != nil {
		fmt.Printf("loading application config: %v", err)
		os.Exit(1)
	}
	tlsCfg, err := loadKubeTLS()
	if err != nil {
		fmt.Printf("loading TLS config: %v", err)
		os.Exit(1)
	}
	srvr := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  time.Minute * 5,
		WriteTimeout: time.Second * 10,
		TLSConfig:    tlsCfg,
	}
	http.HandleFunc("/", handler)
	if cfg.UseTLS {
		srvr.ListenAndServeTLS(KubeCertLocation, KubeKeyLocation)
	} else {
		http.ListenAndServe(":8080", nil)
	}
}

func loadJsonConfig(configFile string) (*config, error) {
	conf := config{}
	configData, err := os.ReadFile(configFile)
	if err != nil {
		fmt.Printf("loadJsonConfig: loading config file %s: %v", configFile, err)
		return nil, err
	}
	err = yaml.Unmarshal(configData, &conf)
	if err != nil {
		fmt.Printf("loadJsonConfig: unmarshaling file %s: %v", configFile, err)
		return nil, err
	}
	return &conf, nil
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(fmt.Sprintf("<h2>NIC Demo application, ver: %s</h2>", demoVer)))
}

func getCaCert() ([]byte, error) {
	return os.ReadFile(KubeCertLocation)
}

// https://www.usenix.org/sites/default/files/conference/protected-files/srecon20americas_slides_hahn.pdf
func loadKubeTLS() (*tls.Config, error) {
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
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    srvrPool,
		RootCAs:      srvrPool,
	}, nil
}

// =========================================================

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
