package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const Undefined = "undefined"

type Config struct {
	IncludeLocal bool   `json:"include_local"`
	Nodes        []Node `json:"nodes"`
}

type Node struct {
	IP   string    `json:"ip"`
	Zone string    `json:"zone"`
	Apps []AppPort `json:"apps"`
}

type AppPort struct {
	Port int16  `json:"port"`
	Role string `json:"role"`
}

type AppKey struct {
	IP   string
	Port string
}

type AppMetrics struct {
	In  prometheus.Observer
	Out prometheus.Observer
}

func main() {
	initGlobal()

	prometheus.MustRegister(TrafficPacketDataBytes)
	prometheus.MustRegister(TrafficDroppedPackets)

	handle, err := pcap.OpenLive(G.Options.Interface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("open device: ", err)
	}
	err = handle.SetBPFFilter(G.Filter)
	if err != nil {
		log.Fatal("set bpf filter: ", err)
	}
	pkts := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	for i := 0; i < G.Options.Workers; i++ {
		go func() {
			for pkt := range pkts {
				networkLayer := pkt.NetworkLayer()
				if networkLayer == nil {
					continue
				}
				transportLayer := pkt.TransportLayer()
				if transportLayer == nil {
					continue
				}
				networkFlow := networkLayer.NetworkFlow()
				transportFlow := transportLayer.TransportFlow()
				srcKey := AppKey{networkFlow.Src().String(), transportFlow.Src().String()}
				if m, ok := G.Index[srcKey]; ok {
					m.In.Observe(float64(len(transportLayer.LayerPayload())))
					continue
				}
				dstKey := AppKey{networkFlow.Dst().String(), transportFlow.Dst().String()}
				if m, ok := G.Index[dstKey]; ok {
					m.Out.Observe(float64(len(transportLayer.LayerPayload())))
					continue
				}
				TrafficDroppedPackets.WithLabelValues(srcKey.IP+":"+srcKey.Port, dstKey.IP+":"+dstKey.Port).Inc()
			}
		}()
	}

	http.Handle("/metrics", promhttp.Handler())
	log.Print("listen on ", G.Options.Addr)
	log.Fatal(http.ListenAndServe(G.Options.Addr, nil))
}

var (
	TrafficPacketDataBytes = prometheus.NewSummaryVec(prometheus.SummaryOpts{
		Name: "traffic_packet_data_bytes",
	}, []string{"app", "dst", "dir", "src_zone", "dst_zone", "cross_zone"})
	TrafficDroppedPackets = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "traffic_dropped_packets_total",
	}, []string{"src", "dst"})
)

var G struct {
	Options struct {
		Interface string
		Config    string
		Zone      string
		Addr      string
		Workers   int
	}
	Config  Config
	Current int
	Filter  string
	Index   map[AppKey]*AppMetrics
}

func initGlobal() {
	flag.StringVar(&G.Options.Interface, "i", "eth0", "interface to watch")
	flag.StringVar(&G.Options.Config, "c", "config.json", "config file")
	flag.StringVar(&G.Options.Zone, "z", Undefined, "zone of current node")
	flag.StringVar(&G.Options.Addr, "a", ":6060", "listen address")
	flag.IntVar(&G.Options.Workers, "w", runtime.NumCPU(), "number of workers")
	flag.Parse()
	if G.Options.Workers < 1 {
		G.Options.Workers = 1
	}

	iface, err := net.InterfaceByName(G.Options.Interface)
	if err != nil {
		log.Fatalf("find interface by name %q: %v", G.Options.Interface, err)
	}

	initConfig()
	initCurrent(iface)
	initFilter()
	initIndex()

	name := iface.Name
	if G.Current >= 0 {
		name = G.Config.Nodes[G.Current].IP
	}
	log.Printf("trace %s@%s by %q", name, G.Options.Zone, G.Filter)
}

func initConfig() {
	cfgFile, err := os.ReadFile(G.Options.Config)
	if err != nil {
		log.Fatal("read config file: ", err)
	}
	if err = json.Unmarshal(cfgFile, &G.Config); err != nil {
		log.Fatal("parse config file: ", err)
	}
}

func initCurrent(iface *net.Interface) {
	G.Current = -1
	addrs, err := iface.Addrs()
	if err != nil {
		return
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP.String()
		for i, node := range G.Config.Nodes {
			if node.IP == ip {
				G.Current = i
				if G.Options.Zone == Undefined {
					G.Options.Zone = G.Config.Nodes[G.Current].Zone
				}
				return
			}
		}
	}
}

func initFilter() {
	buf := new(strings.Builder)
	for i, node := range G.Config.Nodes {
		if len(node.Apps) == 0 || (G.Current == i && !G.Config.IncludeLocal) {
			continue
		}
		if buf.Len() > 0 {
			buf.WriteString(" or ")
		}
		buf.WriteString(fmt.Sprintf("(host %s and (", node.IP))
		for i, port := range node.Apps {
			if i > 0 {
				buf.WriteString(" or ")
			}
			buf.WriteString(fmt.Sprintf("port %d", port.Port))
		}
		buf.WriteString("))")
	}
	G.Filter = buf.String()
}

func initIndex() {
	G.Index = make(map[AppKey]*AppMetrics)
	for _, node := range G.Config.Nodes {
		for _, app := range node.Apps {
			key := AppKey{node.IP, strconv.Itoa(int(app.Port))}
			name := key.IP + ":" + key.Port
			in := TrafficPacketDataBytes.WithLabelValues(app.Role, name, "in", G.Options.Zone, node.Zone, isCrossZone(node))
			out := TrafficPacketDataBytes.WithLabelValues(app.Role, name, "out", G.Options.Zone, node.Zone, isCrossZone(node))
			G.Index[key] = &AppMetrics{in, out}
		}
	}
}

func isCrossZone(node Node) string {
	if G.Options.Zone == Undefined {
		return Undefined
	}
	return strconv.FormatBool(G.Options.Zone != node.Zone)
}
