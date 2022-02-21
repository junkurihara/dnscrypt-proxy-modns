package main

import (
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"math/rand"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jedisct1/dlog"
	clocksmith "github.com/jedisct1/go-clocksmith"
	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/lifenjoiner/ewma"
	"github.com/miekg/dns"
	"golang.org/x/crypto/ed25519"
)

const (
	RTTEwmaDecay = 10.0
)

type RegisteredServer struct {
	name        string
	stamp       stamps.ServerStamp
	description string
}

type ServerBugs struct {
	fragmentsBlocked bool
}

type DOHClientCreds struct {
	clientCert string
	clientKey  string
	rootCA     string
}

type ServerInfo struct {
	DOHClientCreds     DOHClientCreds
	lastActionTS       time.Time
	rtt                *ewma.EWMA
	Name               string
	HostName           string
	UDPAddr            *net.UDPAddr
	TCPAddr            *net.TCPAddr
	Relay              *Relay
	URL                *url.URL
	initialRtt         int
	Timeout            time.Duration
	CryptoConstruction CryptoConstruction
	ServerPk           [32]byte
	SharedKey          [32]byte
	MagicQuery         [8]byte
	knownBugs          ServerBugs
	Proto              stamps.StampProtoType
	useGet             bool
	odohTargetConfigs  []ODoHTargetConfig
}

type LBStrategy interface {
	getCandidate(serversCount int) int
	getActiveCount(serversCount int) int
}

type LBStrategyP2 struct{}

func (LBStrategyP2) getCandidate(serversCount int) int {
	return rand.Intn(Min(serversCount, 2))
}

func (LBStrategyP2) getActiveCount(serversCount int) int {
	return Min(serversCount, 2)
}

type LBStrategyPN struct{ n int }

func (s LBStrategyPN) getCandidate(serversCount int) int {
	return rand.Intn(Min(serversCount, s.n))
}

func (s LBStrategyPN) getActiveCount(serversCount int) int {
	return Min(serversCount, s.n)
}

type LBStrategyPH struct{}

func (LBStrategyPH) getCandidate(serversCount int) int {
	return rand.Intn(Max(Min(serversCount, 2), serversCount/2))
}

func (LBStrategyPH) getActiveCount(serversCount int) int {
	return Max(Min(serversCount, 2), serversCount/2)
}

type LBStrategyFirst struct{}

func (LBStrategyFirst) getCandidate(int) int {
	return 0
}

func (LBStrategyFirst) getActiveCount(int) int {
	return 1
}

type LBStrategyRandom struct{}

func (LBStrategyRandom) getCandidate(serversCount int) int {
	return rand.Intn(serversCount)
}

func (LBStrategyRandom) getActiveCount(serversCount int) int {
	return serversCount
}

var DefaultLBStrategy = LBStrategyP2{}

type ServerStampWithMeta struct {
	Nexthop bool
	stamps.ServerStamp
}
type DNSCryptRelay struct {
	RelayUDPAddr *net.UDPAddr
	RelayTCPAddr *net.TCPAddr
	Nexthop      bool
}

type DNSCryptRelayIPPort struct {
	RelayIP   net.IP
	RelayPort int
}

type ODoHRelay struct {
	URL *url.URL
}

type Relay struct {
	Proto    stamps.StampProtoType
	Dnscrypt []*DNSCryptRelay
	ODoH     *ODoHRelay
}

type ServersInfo struct {
	sync.RWMutex
	inner             []*ServerInfo
	registeredServers []RegisteredServer
	registeredRelays  []RegisteredServer
	lbStrategy        LBStrategy
	lbEstimator       bool
}

func NewServersInfo() ServersInfo {
	return ServersInfo{lbStrategy: DefaultLBStrategy, lbEstimator: true, registeredServers: make([]RegisteredServer, 0), registeredRelays: make([]RegisteredServer, 0)}
}

func (serversInfo *ServersInfo) registerServer(name string, stamp stamps.ServerStamp) {
	newRegisteredServer := RegisteredServer{name: name, stamp: stamp}
	serversInfo.Lock()
	defer serversInfo.Unlock()
	for i, oldRegisteredServer := range serversInfo.registeredServers {
		if oldRegisteredServer.name == name {
			serversInfo.registeredServers[i] = newRegisteredServer
			return
		}
	}
	serversInfo.registeredServers = append(serversInfo.registeredServers, newRegisteredServer)
}

func (serversInfo *ServersInfo) registerRelay(name string, stamp stamps.ServerStamp) {
	newRegisteredServer := RegisteredServer{name: name, stamp: stamp}
	serversInfo.Lock()
	defer serversInfo.Unlock()
	for i, oldRegisteredServer := range serversInfo.registeredRelays {
		if oldRegisteredServer.name == name {
			serversInfo.registeredRelays[i] = newRegisteredServer
			return
		}
	}
	serversInfo.registeredRelays = append(serversInfo.registeredRelays, newRegisteredServer)
}

func (serversInfo *ServersInfo) refreshServer(proxy *Proxy, name string, stamp stamps.ServerStamp) error {
	serversInfo.RLock()
	isNew := true
	for _, oldServer := range serversInfo.inner {
		if oldServer.Name == name {
			isNew = false
			break
		}
	}
	serversInfo.RUnlock()
	newServer, err := fetchServerInfo(proxy, name, stamp, isNew)
	if err != nil {
		return err
	}
	if name != newServer.Name {
		dlog.Fatalf("[%s] != [%s]", name, newServer.Name)
	}
	newServer.rtt = ewma.NewMovingAverage(RTTEwmaDecay)
	newServer.rtt.Set(float64(newServer.initialRtt))
	isNew = true
	serversInfo.Lock()
	for i, oldServer := range serversInfo.inner {
		if oldServer.Name == name {
			serversInfo.inner[i] = &newServer
			isNew = false
			break
		}
	}
	serversInfo.Unlock()
	if isNew {
		serversInfo.Lock()
		serversInfo.inner = append(serversInfo.inner, &newServer)
		serversInfo.Unlock()
		proxy.serversInfo.registerServer(name, stamp)
	}

	return nil
}

func (serversInfo *ServersInfo) refresh(proxy *Proxy) (int, error) {
	dlog.Debug("Refreshing certificates")
	serversInfo.RLock()
	registeredServers := serversInfo.registeredServers
	serversInfo.RUnlock()
	liveServers := 0
	var err error
	for _, registeredServer := range registeredServers {
		if err = serversInfo.refreshServer(proxy, registeredServer.name, registeredServer.stamp); err == nil {
			liveServers++
		}
	}
	serversInfo.Lock()
	sort.SliceStable(serversInfo.inner, func(i, j int) bool {
		return serversInfo.inner[i].initialRtt < serversInfo.inner[j].initialRtt
	})
	inner := serversInfo.inner
	innerLen := len(inner)
	if innerLen > 1 {
		dlog.Notice("Sorted latencies:")
		for i := 0; i < innerLen; i++ {
			dlog.Noticef("- %5dms %s", inner[i].initialRtt, inner[i].Name)
		}
	}
	if innerLen > 0 {
		dlog.Noticef("Server with the lowest initial latency: %s (rtt: %dms)", inner[0].Name, inner[0].initialRtt)
	}
	serversInfo.Unlock()
	return liveServers, err
}

func (serversInfo *ServersInfo) estimatorUpdate() {
	// serversInfo.RWMutex is assumed to be Locked
	serversCount := len(serversInfo.inner)
	activeCount := serversInfo.lbStrategy.getActiveCount(serversCount)
	if activeCount == serversCount {
		return
	}
	candidate, currentActive := rand.Intn(serversCount-activeCount)+activeCount, rand.Intn(activeCount)
	candidateRtt, currentActiveRtt := serversInfo.inner[candidate].rtt.Value(), serversInfo.inner[currentActive].rtt.Value()
	if currentActiveRtt < 0 {
		currentActiveRtt = candidateRtt
		serversInfo.inner[currentActive].rtt.Set(currentActiveRtt)
	}
	partialSort := false
	if candidateRtt < currentActiveRtt {
		serversInfo.inner[candidate], serversInfo.inner[currentActive] = serversInfo.inner[currentActive], serversInfo.inner[candidate]
		dlog.Debugf("New preferred candidate: %s (RTT: %d vs previous: %d)", serversInfo.inner[currentActive].Name, int(candidateRtt), int(currentActiveRtt))
		partialSort = true
	} else if candidateRtt > 0 && candidateRtt >= (serversInfo.inner[0].rtt.Value()+serversInfo.inner[activeCount-1].rtt.Value())/2.0*4.0 {
		if time.Since(serversInfo.inner[candidate].lastActionTS) > time.Duration(1*time.Minute) {
			serversInfo.inner[candidate].rtt.Add(candidateRtt / 2.0)
			dlog.Debugf("Giving a new chance to candidate [%s], lowering its RTT from %d to %d (best: %d)", serversInfo.inner[candidate].Name, int(candidateRtt), int(serversInfo.inner[candidate].rtt.Value()), int(serversInfo.inner[0].rtt.Value()))
			partialSort = true
		}
	}
	if partialSort {
		for i := 1; i < serversCount; i++ {
			if serversInfo.inner[i-1].rtt.Value() > serversInfo.inner[i].rtt.Value() {
				serversInfo.inner[i-1], serversInfo.inner[i] = serversInfo.inner[i], serversInfo.inner[i-1]
			}
		}
	}
}

func (serversInfo *ServersInfo) getOne() *ServerInfo {
	serversInfo.Lock()
	serversCount := len(serversInfo.inner)
	if serversCount <= 0 {
		serversInfo.Unlock()
		return nil
	}
	if serversInfo.lbEstimator {
		serversInfo.estimatorUpdate()
	}
	candidate := serversInfo.lbStrategy.getCandidate(serversCount)
	serverInfo := serversInfo.inner[candidate]
	dlog.Debugf("Using candidate [%s] RTT: %d", (*serverInfo).Name, int((*serverInfo).rtt.Value()))
	serversInfo.Unlock()

	return serverInfo
}

func fetchServerInfo(proxy *Proxy, name string, stamp stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	if stamp.Proto == stamps.StampProtoTypeDNSCrypt {
		return fetchDNSCryptServerInfo(proxy, name, stamp, isNew)
	} else if stamp.Proto == stamps.StampProtoTypeDoH {
		return fetchDoHServerInfo(proxy, name, stamp, isNew)
	} else if stamp.Proto == stamps.StampProtoTypeODoHTarget {
		return fetchODoHTargetInfo(proxy, name, stamp, isNew)
	}
	return ServerInfo{}, fmt.Errorf("Unsupported protocol for [%s]: [%s]", name, stamp.Proto.String())
}

// func findFarthestRoute(proxy *Proxy, name string, relayStamps []*stamps.ServerStamp) *stamps.ServerStamp {
func findFarthestRoute(proxy *Proxy, name string, relayStamps []*ServerStampWithMeta) *ServerStampWithMeta {
	serverIdx := -1
	proxy.serversInfo.RLock()
	for i, registeredServer := range proxy.serversInfo.registeredServers {
		if registeredServer.name == name {
			serverIdx = i
			break
		}
	}
	if serverIdx < 0 {
		return nil
	}
	server := proxy.serversInfo.registeredServers[serverIdx]
	proxy.serversInfo.RUnlock()

	// Fall back to random relays until the logic is implementeed for non-DNSCrypt relays
	if server.stamp.Proto == stamps.StampProtoTypeODoHTarget {
		candidates := make([]int, 0)
		for relayIdx, relayStamp := range relayStamps {
			if relayStamp.Proto != stamps.StampProtoTypeODoHRelay {
				continue
			}
			candidates = append(candidates, relayIdx)
		}
		return relayStamps[candidates[rand.Intn(len(candidates))]]
	} else if server.stamp.Proto != stamps.StampProtoTypeDNSCrypt {
		return nil
	}

	// Anonymized DNSCrypt relays
	serverAddrStr, _ := ExtractHostAndPort(server.stamp.ServerAddrStr, 443)
	serverAddr := net.ParseIP(serverAddrStr)
	if serverAddr == nil {
		return nil
	}
	// if len(proxy.serversInfo.registeredRelays) == 0 {
	if len(relayStamps) == 0 {
		return nil
	}
	bestRelayIdxs := make([]int, 0)
	bestRelaySamePrefixBits := 128
	for relayIdx := range relayStamps {
		if relayStamps[relayIdx].Proto != stamps.StampProtoTypeDNSCryptRelay {
			continue
		}
		relayAddrStr, _ := ExtractHostAndPort(relayStamps[relayIdx].ServerAddrStr, 443)
		relayAddr := net.ParseIP(relayAddrStr)
		if relayAddr == nil {
			continue
		}
		relayIsIPv6 := relayAddr.To4() == nil
		if relayIsIPv6 != (serverAddr.To4() == nil) {
			continue
		}
		firstByte := 0
		if !relayIsIPv6 {
			firstByte = 12
		}
		samePrefixBits := 0
		for i := firstByte; i < 16; i++ {
			x := serverAddr[i] ^ relayAddr[i]
			samePrefixBits += bits.LeadingZeros8(x)
			if x != 0 {
				break
			}
		}
		if samePrefixBits <= bestRelaySamePrefixBits {
			bestRelaySamePrefixBits = samePrefixBits
			bestRelayIdxs = append(bestRelayIdxs, relayIdx)
		}
	}
	return relayStamps[bestRelayIdxs[rand.Intn(len(bestRelayIdxs))]]
}

func relayProtoForServerProto(proto stamps.StampProtoType) (stamps.StampProtoType, error) {
	switch proto {
	case stamps.StampProtoTypeDNSCrypt:
		return stamps.StampProtoTypeDNSCryptRelay, nil
	case stamps.StampProtoTypeODoHTarget:
		return stamps.StampProtoTypeODoHRelay, nil
	default:
		return 0, errors.New("protocol cannot be anonymized")
	}
}

func route(proxy *Proxy, name string, serverProto stamps.StampProtoType) (*Relay, error) {
	routes := proxy.routes
	if routes == nil {
		return nil, nil
	}
	wildcard := false
	relays, ok := (*routes)[name]
	if !ok {
		wildcard = true
		relays, ok = (*routes)["*"]
	}
	if !ok || len(relays) == 0 {
		return nil, nil
	}

	relayProto, err := relayProtoForServerProto(serverProto)
	if err != nil {
		dlog.Errorf("Server [%v]'s protocol doesn't support anonymization", name)
		return nil, nil
	}
	//relayStamps := make([]stamps.ServerStamp, 0)
	relayStamps := make([]ServerStampWithMeta, 0)
	for _, relay := range relays {
		stamp, err := stamps.NewServerStampFromString(relay.RelayName)
		if err == nil {
			relayStamp := ServerStampWithMeta{Nexthop: relay.Nexthop, ServerStamp: stamp}
			if relayStamp.Proto == relayProto {
				relayStamps = append(relayStamps, relayStamp)
			}
		} else if relay.RelayName == "*" {
			proxy.serversInfo.RLock()
			for _, registeredServer := range proxy.serversInfo.registeredRelays {
				if registeredServer.stamp.Proto == relayProto {
					relayStamps = append(relayStamps, ServerStampWithMeta{Nexthop: relay.Nexthop, ServerStamp: registeredServer.stamp})
				}
			}
			proxy.serversInfo.RUnlock()
			wildcard = true
			// break
		} else {
			proxy.serversInfo.RLock()
			for _, registeredServer := range proxy.serversInfo.registeredRelays {
				if registeredServer.name == relay.RelayName && registeredServer.stamp.Proto == relayProto {
					relayStamps = append(relayStamps, ServerStampWithMeta{Nexthop: relay.Nexthop, ServerStamp: registeredServer.stamp})
					break
				}
			}
			for _, registeredServer := range proxy.serversInfo.registeredServers {
				if registeredServer.name == relay.RelayName && registeredServer.stamp.Proto == relayProto {
					relayStamps = append(relayStamps, ServerStampWithMeta{Nexthop: relay.Nexthop, ServerStamp: registeredServer.stamp})
					break
				}
			}
			proxy.serversInfo.RUnlock()
		}
	}

	// remove all duplication from relaystamps
	relayStampsNoDup := make([]ServerStampWithMeta, 0, len(relayStamps))
	type DupCheck struct {
		encountered bool
		storedIdx   int
	}
	dupCheck := map[string]DupCheck{}
	cnt := 0
	for _, v := range relayStamps {
		if check := dupCheck[v.ServerStamp.String()]; !check.encountered {
			dupCheck[v.ServerStamp.String()] = DupCheck{encountered: true, storedIdx: cnt}
			relayStampsNoDup = append(relayStampsNoDup, v)
			cnt++
		} else {
			relayStampsNoDup[check.storedIdx].Nexthop = relayStampsNoDup[check.storedIdx].Nexthop || v.Nexthop
		}
	}

	if len(relayStampsNoDup) == 0 {
		dlog.Warnf("Empty relay set for [%v]", name)
		return nil, nil
	}

	dlog.Debugf(
		"Choosing relay candidates for [%v] (%v) - wildcard: %v, relayRandomization: %v",
		name, serverProto.String(), wildcard, proxy.anonRelayRandomization,
	)

	// filtering with serverProto
	// var filteredStamps [](*stamps.ServerStampWith)
	var filteredStamps [](*ServerStampWithMeta)
	for i, stamp := range relayStampsNoDup {
		if serverProto == stamp.Proto ||
			(serverProto == stamps.StampProtoTypeDNSCrypt && stamp.Proto == stamps.StampProtoTypeDNSCryptRelay) ||
			(serverProto == stamps.StampProtoTypeODoHTarget && stamp.Proto == stamps.StampProtoTypeODoHRelay) {
			filteredStamps = append(filteredStamps, &relayStampsNoDup[i])
		}
	}
	dlog.Debugf("Relay candidates supporting [%v]: %v", serverProto.String(), filteredStamps)

	// var relayCandidateStamps [](*stamps.ServerStamp)
	var relayCandidateStamps [](*ServerStampWithMeta)
	if proxy.anonRelayRandomization || proxy.anonSpecifiedNexthop {
		// if relay_randomization is true, non-sorted. ordering will be done on-demand.
		// proxy.determineRelayOrder specified the order of relaying
		for i := range filteredStamps {
			relayCandidateStamps = append(relayCandidateStamps, filteredStamps[i])
		}
	} else if !wildcard || len(filteredStamps) == 1 {
		// for specific servers or only one relay, only nexthop is fixed
		var relayIdx = rand.Intn(len(filteredStamps))
		relayCandidateStamps = append(relayCandidateStamps, filteredStamps[relayIdx])
		for i := 0; i < len(filteredStamps); i++ {
			if i != relayIdx {
				relayCandidateStamps = append(relayCandidateStamps, filteredStamps[i])
			}
		}
	} else {
		// otherwise, farthest relay is chosen
		farthest := findFarthestRoute(proxy, name, filteredStamps)
		relayCandidateStamps = append(relayCandidateStamps, farthest)
		for i := 0; i < len(filteredStamps); i++ {
			if filteredStamps[i] != farthest {
				relayCandidateStamps = append(relayCandidateStamps, filteredStamps[i])
			}
		}
	}
	if len(relayCandidateStamps) == 0 {
		return nil, fmt.Errorf("No valid relay for server [%v]", name)
	}
	dlog.Debugf("Stamps of chosen relay candidates for [%v]: %v", name, relayCandidateStamps)

	/// maybe not required? only used for print.
	var relayNamesForPrint []string
	proxy.serversInfo.RLock()
	for i := range relayCandidateStamps {
		relayName := relayCandidateStamps[i].ServerAddrStr
		for _, registeredServer := range proxy.serversInfo.registeredRelays {
			if registeredServer.stamp.Proto == relayProto && registeredServer.stamp.ServerAddrStr == relayCandidateStamps[i].ServerAddrStr {
				relayName = registeredServer.name
				break
			}
		}
		relayNamesForPrint = append(relayNamesForPrint, relayName)
	}

	proxy.serversInfo.RUnlock()
	switch serverProto {
	case stamps.StampProtoTypeDNSCrypt:
		var relayAddrs []*DNSCryptRelay
		for _, stamp := range relayCandidateStamps {
			relayUDPAddr, err := net.ResolveUDPAddr("udp", stamp.ServerAddrStr)
			if err != nil {
				return nil, err
			}
			relayTCPAddr, err := net.ResolveTCPAddr("tcp", stamp.ServerAddrStr)
			if err != nil {
				return nil, err
			}
			relayAddrs = append(relayAddrs, &DNSCryptRelay{RelayUDPAddr: relayUDPAddr, RelayTCPAddr: relayTCPAddr, Nexthop: stamp.Nexthop})
		}
		dlog.Noticef("Anonymizing queries to [%v] via relays [%v]", name, relayNamesForPrint)
		return &Relay{
			Proto:    stamps.StampProtoTypeDNSCryptRelay,
			Dnscrypt: relayAddrs,
		}, nil
	case stamps.StampProtoTypeODoHRelay:
		// TODO: relay_randomization here by randomizing [0]
		relayBaseURL, err := url.Parse("https://" + url.PathEscape(relayCandidateStamps[0].ProviderName) + relayCandidateStamps[0].Path)
		if err != nil {
			return nil, err
		}
		var relayURLforTarget *url.URL
		for _, server := range proxy.registeredServers {
			if server.name != name || server.stamp.Proto != stamps.StampProtoTypeODoHTarget {
				continue
			}
			qs := relayBaseURL.Query()
			qs.Add("targethost", server.stamp.ProviderName)
			qs.Add("targetpath", server.stamp.Path)
			tmp := *relayBaseURL
			tmp.RawQuery = qs.Encode()
			relayURLforTarget = &tmp
			break
		}
		// TODO: relay_randomization here by randomizing [0]
		if relayURLforTarget == nil {
			return nil, fmt.Errorf("Relay [%v] not found", relayNamesForPrint[0])
		}
		if len(relayCandidateStamps[0].ServerAddrStr) > 0 {
			ipOnly, _ := ExtractHostAndPort(relayCandidateStamps[0].ServerAddrStr, -1)
			if ip := ParseIP(ipOnly); ip != nil {
				host, _ := ExtractHostAndPort(relayCandidateStamps[0].ProviderName, -1)
				proxy.xTransport.saveCachedIP(host, ip, -1*time.Second)
			}
		}
		dlog.Noticef("Anonymizing queries for [%v] via [%v]", name, relayNamesForPrint[0])
		return &Relay{Proto: stamps.StampProtoTypeODoHRelay, ODoH: &ODoHRelay{
			URL: relayURLforTarget,
		}}, nil
	}
	return nil, fmt.Errorf("Invalid relay set for server [%v]", name)
}

func fetchDNSCryptServerInfo(proxy *Proxy, name string, stamp stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	if len(stamp.ServerPk) != ed25519.PublicKeySize {
		serverPk, err := hex.DecodeString(strings.Replace(string(stamp.ServerPk), ":", "", -1))
		if err != nil || len(serverPk) != ed25519.PublicKeySize {
			dlog.Fatalf("Unsupported public key for [%s]: [%s]", name, stamp.ServerPk)
		}
		dlog.Warnf("Public key [%s] shouldn't be hex-encoded any more", string(stamp.ServerPk))
		stamp.ServerPk = serverPk
	}
	knownBugs := ServerBugs{}
	for _, buggyServerName := range proxy.serversBlockingFragments {
		if buggyServerName == name {
			knownBugs.fragmentsBlocked = true
			dlog.Infof("Known bug in [%v]: fragmented questions over UDP are blocked", name)
			break
		}
	}
	relay, err := route(proxy, name, stamp.Proto)
	if err != nil {
		return ServerInfo{}, err
	}
	var dnscryptRelay []*DNSCryptRelay
	if relay != nil {
		dnscryptRelay = relay.Dnscrypt
	}
	certInfo, rtt, fragmentsBlocked, err := FetchCurrentDNSCryptCert(proxy, &name, proxy.mainProto, stamp.ServerPk, stamp.ServerAddrStr, stamp.ProviderName, isNew, dnscryptRelay, knownBugs)
	if !knownBugs.fragmentsBlocked && fragmentsBlocked {
		dlog.Debugf("[%v] drops fragmented queries", name)
		knownBugs.fragmentsBlocked = true
	}
	if knownBugs.fragmentsBlocked && relay != nil && relay.Dnscrypt != nil {
		relay = nil
		if proxy.skipAnonIncompatibleResolvers {
			dlog.Infof("[%v] couldn't be reached anonymously, it will be ignored", name)
			return ServerInfo{}, errors.New("Resolver couldn't be reached anonymously")
		}
		dlog.Warnf("[%v] couldn't be reached anonymously", name)
	}
	if err != nil {
		return ServerInfo{}, err
	}
	remoteUDPAddr, err := net.ResolveUDPAddr("udp", stamp.ServerAddrStr)
	if err != nil {
		return ServerInfo{}, err
	}
	remoteTCPAddr, err := net.ResolveTCPAddr("tcp", stamp.ServerAddrStr)
	if err != nil {
		return ServerInfo{}, err
	}
	return ServerInfo{
		Proto:              stamps.StampProtoTypeDNSCrypt,
		MagicQuery:         certInfo.MagicQuery,
		ServerPk:           certInfo.ServerPk,
		SharedKey:          certInfo.SharedKey,
		CryptoConstruction: certInfo.CryptoConstruction,
		Name:               name,
		Timeout:            proxy.timeout,
		UDPAddr:            remoteUDPAddr,
		TCPAddr:            remoteTCPAddr,
		Relay:              relay,
		initialRtt:         rtt,
		knownBugs:          knownBugs,
	}, nil
}

func dohTestPacket(msgID uint16) []byte {
	msg := dns.Msg{}
	msg.SetQuestion(".", dns.TypeNS)
	msg.Id = msgID
	msg.MsgHdr.RecursionDesired = true
	msg.SetEdns0(uint16(MaxDNSPacketSize), false)
	ext := new(dns.EDNS0_PADDING)
	ext.Padding = make([]byte, 16)
	crypto_rand.Read(ext.Padding)
	edns0 := msg.IsEdns0()
	edns0.Option = append(edns0.Option, ext)
	body, err := msg.Pack()
	if err != nil {
		dlog.Fatal(err)
	}
	return body
}

func dohNXTestPacket(msgID uint16) []byte {
	msg := dns.Msg{}
	qName := make([]byte, 16)
	charset := "abcdefghijklmnopqrstuvwxyz"
	for i := range qName {
		qName[i] = charset[rand.Intn(len(charset))]
	}
	msg.SetQuestion(string(qName)+".test.dnscrypt.", dns.TypeNS)
	msg.Id = msgID
	msg.MsgHdr.RecursionDesired = true
	msg.SetEdns0(uint16(MaxDNSPacketSize), false)
	ext := new(dns.EDNS0_PADDING)
	ext.Padding = make([]byte, 16)
	crypto_rand.Read(ext.Padding)
	edns0 := msg.IsEdns0()
	edns0.Option = append(edns0.Option, ext)
	body, err := msg.Pack()
	if err != nil {
		dlog.Fatal(err)
	}
	return body
}

func fetchDoHServerInfo(proxy *Proxy, name string, stamp stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	// If an IP has been provided, use it forever.
	// Or else, if the fallback server and the DoH server are operated
	// by the same entity, it could provide a unique IPv6 for each client
	// in order to fingerprint clients across multiple IP addresses.
	if len(stamp.ServerAddrStr) > 0 {
		ipOnly, _ := ExtractHostAndPort(stamp.ServerAddrStr, -1)
		if ip := ParseIP(ipOnly); ip != nil {
			host, _ := ExtractHostAndPort(stamp.ProviderName, -1)
			proxy.xTransport.saveCachedIP(host, ip, -1*time.Second)
		}
	}
	url := &url.URL{
		Scheme: "https",
		Host:   stamp.ProviderName,
		Path:   stamp.Path,
	}
	body := dohTestPacket(0xcafe)
	useGet := false
	if _, _, _, _, err := proxy.xTransport.DoHQuery(useGet, url, body, proxy.timeout); err != nil {
		useGet = true
		if _, _, _, _, err := proxy.xTransport.DoHQuery(useGet, url, body, proxy.timeout); err != nil {
			return ServerInfo{}, err
		}
		dlog.Debugf("Server [%s] doesn't appear to support POST; falling back to GET requests", name)
	}
	body = dohNXTestPacket(0xcafe)
	serverResponse, _, tls, rtt, err := proxy.xTransport.DoHQuery(useGet, url, body, proxy.timeout)
	if err != nil {
		dlog.Infof("[%s] [%s]: %v", name, url, err)
		return ServerInfo{}, err
	}
	if tls == nil || !tls.HandshakeComplete {
		return ServerInfo{}, errors.New("TLS handshake failed")
	}
	msg := dns.Msg{}
	if err := msg.Unpack(serverResponse); err != nil {
		dlog.Warnf("[%s]: %v", name, err)
		return ServerInfo{}, err
	}
	if msg.Rcode != dns.RcodeNameError {
		dlog.Criticalf("[%s] may be a lying resolver", name)
	}
	protocol := tls.NegotiatedProtocol
	if len(protocol) == 0 {
		protocol = "http/1.x"
	}
	if strings.HasPrefix(protocol, "http/1.") {
		dlog.Warnf("[%s] does not support HTTP/2", name)
	}
	dlog.Infof("[%s] TLS version: %x - Protocol: %v - Cipher suite: %v", name, tls.Version, protocol, tls.CipherSuite)
	showCerts := proxy.showCerts
	found := false
	var wantedHash [32]byte
	for _, cert := range tls.PeerCertificates {
		h := sha256.Sum256(cert.RawTBSCertificate)
		if showCerts {
			dlog.Noticef("Advertised cert: [%s] [%x]", cert.Subject, h)
		} else {
			dlog.Debugf("Advertised cert: [%s] [%x]", cert.Subject, h)
		}
		for _, hash := range stamp.Hashes {
			if len(hash) == len(wantedHash) {
				copy(wantedHash[:], hash)
				if h == wantedHash {
					found = true
					break
				}
			}
		}
		if found {
			break
		}
	}
	if !found && len(stamp.Hashes) > 0 {
		dlog.Criticalf("[%s] Certificate hash [%x] not found", name, wantedHash)
		return ServerInfo{}, fmt.Errorf("Certificate hash not found")
	}
	if len(serverResponse) < MinDNSPacketSize || len(serverResponse) > MaxDNSPacketSize ||
		serverResponse[0] != 0xca || serverResponse[1] != 0xfe || serverResponse[4] != 0x00 || serverResponse[5] != 0x01 {
		dlog.Info("Webserver returned an unexpected response")
		return ServerInfo{}, errors.New("Webserver returned an unexpected response")
	}
	xrtt := int(rtt.Nanoseconds() / 1000000)
	if isNew {
		dlog.Noticef("[%s] OK (DoH) - rtt: %dms", name, xrtt)
	} else {
		dlog.Infof("[%s] OK (DoH) - rtt: %dms", name, xrtt)
	}
	return ServerInfo{
		Proto:      stamps.StampProtoTypeDoH,
		Name:       name,
		Timeout:    proxy.timeout,
		URL:        url,
		HostName:   stamp.ProviderName,
		initialRtt: xrtt,
		useGet:     useGet,
	}, nil
}

func fetchTargetConfigsFromWellKnown(proxy *Proxy, url *url.URL) ([]ODoHTargetConfig, error) {
	bin, statusCode, _, _, err := proxy.xTransport.Get(url, "application/binary", 0)
	if err != nil {
		return nil, err
	}
	if statusCode < 200 || statusCode >= 300 {
		return nil, fmt.Errorf("HTTP status code was %v", statusCode)
	}
	return parseODoHTargetConfigs(bin)
}

func _fetchODoHTargetInfo(proxy *Proxy, name string, stamp stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	configURL := &url.URL{Scheme: "https", Host: stamp.ProviderName, Path: "/.well-known/odohconfigs"}
	odohTargetConfigs, err := fetchTargetConfigsFromWellKnown(proxy, configURL)
	if err != nil {
		dlog.Debug(configURL)
		return ServerInfo{}, fmt.Errorf("[%s] didn't return an ODoH configuration - [%v]", name, err)
	} else if len(odohTargetConfigs) == 0 {
		dlog.Debug(configURL)
		return ServerInfo{}, fmt.Errorf("[%s] has an empty ODoH configuration", name)
	}

	relay, err := route(proxy, name, stamp.Proto)
	if err != nil {
		return ServerInfo{}, err
	}

	if relay == nil {
		dlog.Criticalf("No relay defined for [%v] - Configuring a relay is required for ODoH servers (see the `[anonymized_dns]` section)", name)
		return ServerInfo{}, errors.New("No ODoH relay")
	} else {
		if relay.ODoH == nil {
			dlog.Criticalf("Wrong relay type defined for [%v] - ODoH servers require an ODoH relay", name)
			return ServerInfo{}, errors.New("Wrong ODoH relay type")
		}
	}

	dlog.Debugf("Pausing after ODoH configuration retrieval")
	delay := time.Duration(rand.Intn(5*1000)) * time.Millisecond
	clocksmith.Sleep(time.Duration(delay))
	dlog.Debugf("Pausing done")

	targetURL := &url.URL{
		Scheme: "https",
		Host:   stamp.ProviderName,
		Path:   stamp.Path,
	}

	workingConfigs := make([]ODoHTargetConfig, 0)
	rand.Shuffle(len(odohTargetConfigs), func(i, j int) {
		odohTargetConfigs[i], odohTargetConfigs[j] = odohTargetConfigs[j], odohTargetConfigs[i]
	})
	for _, odohTargetConfig := range odohTargetConfigs {
		url := relay.ODoH.URL

		query := dohTestPacket(0xcafe)
		odohQuery, err := odohTargetConfig.encryptQuery(query)
		if err != nil {
			continue
		}

		useGet := false
		if _, _, _, _, err := proxy.xTransport.ObliviousDoHQuery(useGet, url, odohQuery.odohMessage, proxy.timeout); err != nil {
			useGet = true
			if _, _, _, _, err := proxy.xTransport.ObliviousDoHQuery(useGet, url, odohQuery.odohMessage, proxy.timeout); err != nil {
				continue
			}
			dlog.Debugf("Server [%s] doesn't appear to support POST; falling back to GET requests", name)
		}

		query = dohNXTestPacket(0xcafe)
		odohQuery, err = odohTargetConfig.encryptQuery(query)
		if err != nil {
			continue
		}

		responseBody, responseCode, tls, rtt, err := proxy.xTransport.ObliviousDoHQuery(useGet, url, odohQuery.odohMessage, proxy.timeout)
		if err != nil {
			continue
		}
		if responseCode == 401 {
			return ServerInfo{}, fmt.Errorf("Configuration changed during a probe")
		}
		serverResponse, err := odohQuery.decryptResponse(responseBody)
		if err != nil {
			dlog.Warnf("Unable to decrypt response from [%v]: [%v]", name, err)
			continue
		}
		workingConfigs = append(workingConfigs, odohTargetConfig)

		msg := dns.Msg{}
		if err := msg.Unpack(serverResponse); err != nil {
			dlog.Warnf("[%s]: %v", name, err)
			return ServerInfo{}, err
		}
		if msg.Rcode != dns.RcodeNameError {
			dlog.Criticalf("[%s] may be a lying resolver", name)
		}

		protocol := tls.NegotiatedProtocol
		if len(protocol) == 0 {
			protocol = "http/1.x"
		}
		if strings.HasPrefix(protocol, "http/1.") {
			dlog.Warnf("[%s] does not support HTTP/2", name)
		}
		dlog.Infof("[%s] TLS version: %x - Protocol: %v - Cipher suite: %v", name, tls.Version, protocol, tls.CipherSuite)
		showCerts := proxy.showCerts
		found := false
		var wantedHash [32]byte
		for _, cert := range tls.PeerCertificates {
			h := sha256.Sum256(cert.RawTBSCertificate)
			if showCerts {
				dlog.Noticef("Advertised relay cert: [%s] [%x]", cert.Subject, h)
			} else {
				dlog.Debugf("Advertised relay cert: [%s] [%x]", cert.Subject, h)
			}
			for _, hash := range stamp.Hashes {
				if len(hash) == len(wantedHash) {
					copy(wantedHash[:], hash)
					if h == wantedHash {
						found = true
						break
					}
				}
			}
			if found {
				break
			}
		}
		if !found && len(stamp.Hashes) > 0 {
			dlog.Criticalf("[%s] Certificate hash [%x] not found", name, wantedHash)
			return ServerInfo{}, fmt.Errorf("Certificate hash not found")
		}
		if len(serverResponse) < MinDNSPacketSize || len(serverResponse) > MaxDNSPacketSize ||
			serverResponse[0] != 0xca || serverResponse[1] != 0xfe || serverResponse[4] != 0x00 || serverResponse[5] != 0x01 {
			dlog.Info("Webserver returned an unexpected response")
			return ServerInfo{}, errors.New("Webserver returned an unexpected response")
		}
		xrtt := int(rtt.Nanoseconds() / 1000000)
		if isNew {
			dlog.Noticef("[%s] OK (ODoH) - rtt: %dms", name, xrtt)
		} else {
			dlog.Infof("[%s] OK (ODoH) - rtt: %dms", name, xrtt)
		}
		return ServerInfo{
			Proto:             stamps.StampProtoTypeODoHTarget,
			Name:              name,
			Timeout:           proxy.timeout,
			URL:               targetURL,
			HostName:          stamp.ProviderName,
			initialRtt:        xrtt,
			useGet:            useGet,
			Relay:             relay,
			odohTargetConfigs: workingConfigs,
		}, nil
	}
	return ServerInfo{}, fmt.Errorf("No valid network configuration for [%v]", name)
}

func fetchODoHTargetInfo(proxy *Proxy, name string, stamp stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	var err error
	var serverInfo ServerInfo
	for i := 0; i < 3; i += 1 {
		serverInfo, err = _fetchODoHTargetInfo(proxy, name, stamp, isNew)
		if err == nil {
			break
		}
		dlog.Infof("Trying to fetch the [%v] configuration again", name)
	}
	return serverInfo, err
}

func (serverInfo *ServerInfo) noticeFailure(proxy *Proxy) {
	proxy.serversInfo.Lock()
	serverInfo.rtt.Add(float64(proxy.timeout.Nanoseconds() / 1000000))
	proxy.serversInfo.Unlock()
}

func (serverInfo *ServerInfo) noticeBegin(proxy *Proxy) {
	proxy.serversInfo.Lock()
	serverInfo.lastActionTS = time.Now()
	proxy.serversInfo.Unlock()
}

func (serverInfo *ServerInfo) noticeSuccess(proxy *Proxy) {
	now := time.Now()
	proxy.serversInfo.Lock()
	elapsed := now.Sub(serverInfo.lastActionTS)
	elapsedMs := elapsed.Nanoseconds() / 1000000
	if elapsedMs > 0 && elapsed < proxy.timeout {
		serverInfo.rtt.Add(float64(elapsedMs))
	}
	proxy.serversInfo.Unlock()
}
