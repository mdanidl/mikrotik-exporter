package main

import (
	"bytes"
	"errors"
	"flag"
	"io/ioutil"
	"os"
	"strings"

	"fmt"
	"net/http"

	vault "github.com/hashicorp/vault/api"
	"github.com/nshttpd/mikrotik-exporter/collector"
	"github.com/nshttpd/mikrotik-exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	log "github.com/sirupsen/logrus"
)

// single device can be defined via CLI flags, mutliple via config file.
var (
	device        = flag.String("device", "", "single device to monitor")
	address       = flag.String("address", "", "address of the device to monitor")
	user          = flag.String("user", "", "user for authentication with single device")
	password      = flag.String("password", "", "password for authentication for single device")
	logLevel      = flag.String("log-level", "info", "log level")
	logFormat     = flag.String("log-format", "json", "logformat text or json (default json)")
	port          = flag.String("port", ":9436", "port number to listen on")
	metricsPath   = flag.String("path", "/metrics", "path to answer requests on")
	configFile    = flag.String("config-file", "", "config file to load")
	vaultKvPrefix = flag.String("vault-prefix", "", "Path prefix in vault to store router access configuration")
	useVault      = flag.Bool("use-vault", false, "Using vault to retrieve configuration")
	withBgp       = flag.Bool("with-bgp", false, "retrieves BGP routing infrormation")
	withRoutes    = flag.Bool("with-routes", false, "retrieves routing table information")
	withDHCP      = flag.Bool("with-dhcp", false, "retrieves DHCP server metrics")
	withDHCPv6    = flag.Bool("with-dhcpv6", false, "retrieves DHCPv6 server metrics")
	withPools     = flag.Bool("with-pools", false, "retrieves IP(v6) pool metrics")
	withOptics    = flag.Bool("with-optics", false, "retrieves optical diagnostic metrics")
	withWlanSTA   = flag.Bool("with-wlansta", false, "retrieves connected wlan station metrics")
	withWlanIF    = flag.Bool("with-wlanif", false, "retrieves wlan interface metrics")
	timeout       = flag.Duration("timeout", collector.DefaultTimeout, "timeout when connecting to routers")
	tls           = flag.Bool("tls", false, "use tls to connect to routers")
	insecure      = flag.Bool("insecure", false, "skips verification of server certificate when using TLS (not recommended)")
	cfg           *config.Config
)

func init() {
	prometheus.MustRegister(version.NewCollector("mikrotik_exporter"))
}

func main() {
	flag.Parse()

	configureLog()

	c, err := loadConfig()
	if err != nil {
		log.Errorf("Could not load config: %v", err)
		os.Exit(3)
	}
	cfg = c

	startServer()
}

func configureLog() {
	ll, err := log.ParseLevel(*logLevel)
	if err != nil {
		panic(err)
	}

	log.SetLevel(ll)

	if *logFormat == "text" {
		log.SetFormatter(&log.TextFormatter{})
	} else {
		log.SetFormatter(&log.JSONFormatter{})
	}
}

func loadConfig() (*config.Config, error) {
	// Read stuff from Vault first
	c, err := loadConfigFromVault()
	if err != nil {
		return nil, err
	}

	if c != nil {
		return c, nil
	} else {
		// If vault is not configured, try to load it from file
		if *configFile != "" {
			return loadConfigFromFile()
		}
	}

	// In any other case, try to read a single config from flags
	return loadConfigFromFlags()
}

// for now this only validates the existence of the fields
func validMktConfig(s *vault.Secret, v int) bool {
	if v == 2 {
		v2s := s.Data["data"].(map[string]interface{})
		if v2s["address"] == nil || v2s["user"] == nil || v2s["password"] == nil {
			return false
		}
	} else {
		if s.Data["address"] == nil || s.Data["user"] == nil || s.Data["password"] == nil {
			return false
		}
	}
	return true
}

func loadConfigFromVault() (*config.Config, error) {
	v, err := initVault()
	if err != nil {
		log.Fatalf("Could not initialise vault: %v", err)
	}

	// checking mount for kv-v2 strings.Split(*vaultKvPrefix, "/")[0]
	mounts, err := v.Sys().ListMounts()
	prefixSlice := strings.Split(*vaultKvPrefix, "/")
	newListPath := []string{}
	newDataPath := []string{}
	var kvVersion int
	mymount := mounts[prefixSlice[0]+"/"]
	if mymount.Type == "kv" {
		if mymount.Options["version"] == "2" {
			// if kv is v2 let's add the extra path in
			kvVersion = 2
			newListPath = []string{prefixSlice[0], "metadata"}
			newDataPath = []string{prefixSlice[0], "data"}
			newListPath = append(newListPath[:2], append(make([]string, 1), prefixSlice[1:]...)...)
			newDataPath = append(newDataPath[:2], append(make([]string, 1), prefixSlice[1:]...)...)
		} else {
			newListPath = prefixSlice
			newDataPath = prefixSlice
		}
	}
	newListPathString := strings.Join(newListPath, "/")
	newDataPathString := strings.Join(newDataPath, "/")
	listOfSecrets, err := v.Logical().List(newListPathString)
	if err != nil {
		return nil, err
	}
	keySlice := listOfSecrets.Data["keys"]
	deviceSettings := []config.Device{}
	cnf := make(map[string]interface{})
	for _, keyToRead := range keySlice.([]interface{}) {
		secret, err := v.Logical().Read(newDataPathString + "/" + keyToRead.(string))
		if err != nil {
			return nil, err
		}
		if !validMktConfig(secret, kvVersion) {
			err = errors.New("Invalid mikrotik device config found in vault at: " + newDataPathString + "/" + keyToRead.(string))
			log.Fatalf("Validation error: %s", err)
		}
		if kvVersion == 2 {
			cnf = secret.Data["data"].(map[string]interface{})
		} else {
			cnf = secret.Data
		}
		deviceSettings = append(deviceSettings, config.Device{
			Name:     keyToRead.(string),
			Address:  cnf["address"].(string),
			User:     cnf["user"].(string),
			Password: cnf["password"].(string),
		})

	}
	return &config.Config{
		Devices: deviceSettings,
	}, nil
}

func loadConfigFromFile() (*config.Config, error) {
	b, err := ioutil.ReadFile(*configFile)
	if err != nil {
		return nil, err
	}

	return config.Load(bytes.NewReader(b))
}

func loadConfigFromFlags() (*config.Config, error) {
	if *device == "" || *address == "" || *user == "" || *password == "" {
		return nil, fmt.Errorf("missing required param for single device configuration")
	}

	return &config.Config{
		Devices: []config.Device{
			config.Device{
				Name:     *device,
				Address:  *address,
				User:     *user,
				Password: *password,
			},
		},
	}, nil
}

func initVault() (*vault.Client, error) {
	log.Debug("Initialising Vault connection")
	if !*useVault {
		log.Debug("Ignoring vault configuration")
		return nil, nil
	}
	if *vaultKvPrefix == "" {
		log.Fatal("No prefix defined to retrieve mikrotik config from.")
		return nil, errors.New("No prefix defined to retrieve mikrotik config from.")
	}

	// only using the default config options for now, so use Environment variables to configure vault access.
	// visit here for list of available environment variables: https://github.com/hashicorp/vault/blob/984df34ca7b45897ecb5871791e398cc160a4b93/api/client.go#L28
	return vault.NewClient(nil)
}

func startServer() {
	h, err := createMetricsHandler()
	if err != nil {
		log.Fatal(err)
	}
	http.Handle(*metricsPath, h)

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>Mikrotik Exporter</title></head>
			<body>
			<h1>Mikrotik Exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			</body>
			</html>`))
	})

	log.Info("Listening on ", *port)
	log.Fatal(http.ListenAndServe(*port, nil))
}

func createMetricsHandler() (http.Handler, error) {
	opts := collectorOptions()
	nc, err := collector.NewCollector(cfg, opts...)
	if err != nil {
		return nil, err
	}

	registry := prometheus.NewRegistry()
	err = registry.Register(nc)
	if err != nil {
		return nil, err
	}

	return promhttp.HandlerFor(registry,
		promhttp.HandlerOpts{
			ErrorLog:      log.New(),
			ErrorHandling: promhttp.ContinueOnError,
		}), nil
}

func collectorOptions() []collector.Option {
	opts := []collector.Option{}

	if *withBgp || cfg.Features.BGP {
		opts = append(opts, collector.WithBGP())
	}

	if *withRoutes || cfg.Features.Routes {
		opts = append(opts, collector.WithRoutes())
	}

	if *withDHCP || cfg.Features.DHCP {
		opts = append(opts, collector.WithDHCP())
	}

	if *withDHCPv6 || cfg.Features.DHCPv6 {
		opts = append(opts, collector.WithDHCPv6())
	}

	if *withPools || cfg.Features.Pools {
		opts = append(opts, collector.WithPools())
	}

	if *withOptics || cfg.Features.Optics {
		opts = append(opts, collector.WithOptics())
	}

	if *withWlanSTA || cfg.Features.WlanSTA {
		opts = append(opts, collector.WithWlanSTA())
	}

	if *withWlanIF || cfg.Features.WlanIF {
		opts = append(opts, collector.WithWlanIF())
	}

	if *timeout != collector.DefaultTimeout {
		opts = append(opts, collector.WithTimeout(*timeout))
	}

	if *tls {
		opts = append(opts, collector.WithTLS(*insecure))
	}

	return opts
}
