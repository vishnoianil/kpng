/*
Copyright 2022 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ebpf

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/pflag"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	"sigs.k8s.io/kpng/client"
	"sigs.k8s.io/kpng/client/lightdiffstore"

	"github.com/cespare/xxhash"
)

var (
	flag = &pflag.FlagSet{}

	hookPrio        = flag.Int("hook-priority", 0, "nftable hooks priority")
	splitBits       = flag.Int("split-bits", 24, "dispatch services in multiple chains, splitting at the nth bit")
	splitBits6      = flag.Int("split-bits6", 120, "dispatch services in multiple chains, splitting at the nth bit (for IPv6)")
	mapsCount       = flag.Uint64("maps-count", 0x100, "number of endpoints maps to use")
	withTrace       = flag.Bool("trace", false, "enable nft trace")
	clusterCIDRsFlag = flag.StringSlice("cluster-cidrs", []string{"0.0.0.0/0"}, "cluster IPs CIDR that should not be masqueraded")
	
	clusterCIDRsV4   []string
	clusterCIDRsV6   []string

	fullResync = true
)

func BindFlags(flags *pflag.FlagSet) {
	flags.AddFlagSet(flag)
}

// FIXME atomic delete with references are currently buggy, so defer it
const deferDelete = true

// FIXME defer delete also is buggy; having to wait ~1s which is not acceptable...
const canDeleteChains = false


//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ./bpf/cgroup_connect4.c
func ebpfSetup() ebpfController {
	var err error

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		klog.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, &cebpf.CollectionOptions{}); err != nil {
		log.Fatalf("loading objects: %v", err)
	}

	info, err := objs.bpfMaps.V4SvcMap.Info()
	if err != nil {
		klog.Fatalf("Cannot get map info: %v", err)
	}
	klog.Infof("Svc Map Info: %+v with FD %s", info, objs.bpfMaps.V4SvcMap.String())

	info, err = objs.bpfMaps.V4BackendMap.Info()
	if err != nil {
		klog.Fatalf("Cannot get map info: %v", err)
	}
	klog.Infof("Backend Map Info: %+v", info)

	// Get the first-mounted cgroupv2 path.
	cgroupPath, err := detectRootCgroupPath()
	if err != nil {
		log.Fatal(err)
	}

	klog.Infof("Cgroup Path is %s", cgroupPath)

	// Link the proxy program to the default cgroup.
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  cebpf.AttachCGroupInet4Connect,
		Program: objs.Sock4Connect,
	})
	if err != nil {
		klog.Fatal(err)
	}

	klog.Infof("Proxying packets in kernel...")

	return NewEBPFController(objs, l, v1.IPv4Protocol)
}

func PreRun() {
	checkIPTableVersion()

	// parse cluster CIDRs
	clusterCIDRsV4 = make([]string, 0)
	clusterCIDRsV6 = make([]string, 0)
	for _, cidr := range *clusterCIDRsFlag {
		ip, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			klog.Fatalf("bad CIDR given: %q: %v", cidr, err)
		}

		if ip.To4() == nil {
			clusterCIDRsV6 = append(clusterCIDRsV6, ipNet.String())
		} else {
			clusterCIDRsV4 = append(clusterCIDRsV4, ipNet.String())
		}
	}

	klog.Info("cluster CIDRs V4: ", clusterCIDRsV4)
	klog.Info("cluster CIDRs V6: ", clusterCIDRsV6)
}

// detectCgroupPath returns the first-found mount point of type cgroup2
// and stores it in the cgroupPath globalv1 variable.
func detectRootCgroupPath() (string, error) {
	// This corresponds to the host's mount's location in the pod deploying this backend.
	f, err := os.Open("/host-mount/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 not mounted")
}

func (ebc *ebpfController) Cleanup() {
	klog.Info("Cleaning Up EBPF resources")
	ebc.bpfLink.Close()
	ebc.objs.Close()
}

func (ebc *ebpfController) Callback(ch <-chan *client.ServiceEndpoints) {
	// Reset the diffstore before syncing
	ebc.svcMap.Reset(lightdiffstore.ItemDeleted)

	svcCount := 0
	epCount := 0

	start := time.Now()
	defer func() {
		klog.V(1).Infof("%d services and %d endpoints applied in %v", svcCount, epCount, time.Since(start))
	}()

	defer table4.Reset()
	defer table6.Reset()

	renderContexts := []*renderContext{
		newRenderContext(table4, clusterCIDRsV4, net.CIDRMask(*splitBits, 32)),
		newRenderContext(table6, clusterCIDRsV6, net.CIDRMask(*splitBits6, 128)),
	}

	// Populate internal cache based on incoming fullstate information
	for serviceEndpoints := range ch {
		klog.V(5).Infof("Iterating fullstate channel, got: %+v", serviceEndpoints)

		if serviceEndpoints.Service.Type == "ClusterIP" {
			svcCount++
			svcUniqueName := types.NamespacedName{Name: serviceEndpoints.Service.Name, Namespace: serviceEndpoints.Service.Namespace}

			for i := range serviceEndpoints.Service.Ports {
				servicePort := serviceEndpoints.Service.Ports[i]
				svcKey := fmt.Sprintf("%s/%d/%s", svcUniqueName, servicePort.Port, servicePort.Protocol)
				baseSvcInfo := ebc.newBaseServiceInfo(servicePort, serviceEndpoints.Service)
	
				svcEndptRelation := svcEndpointMapping{Svc: baseSvcInfo, Endpoint: serviceEndpoints.Endpoints}
				// JSON encoding of our services + EP information
				svcEndptRelationBytes := new(bytes.Buffer)
				json.NewEncoder(svcEndptRelationBytes).Encode(svcEndptRelation)
	
				// Always update cache regardless of if sync is needed
				// Eventually we'll spawn multiple go routines to handle this
				// (for higher scale scenarios), and then we'll need the data
				// lock for now do it to be safe.
				ebc.mu.Lock()
				ebc.svcMap.Set([]byte(svcKey), xxhash.Sum64(svcEndptRelationBytes.Bytes()), svcEndptRelation)
				ebc.mu.Unlock()
			}
		}

		if serviceEndpoints.Service.Type == "NodePort" {
			svcCount++

			for _, ctx := range renderContexts {
				ctx.addServiceEndpoints(serviceEndpoints)
				epCount += ctx.epCount
			}	
		}

	}

	// Reconcile what we have in ebc.svcInfo to internal cache and ebpf maps
	// The diffstore will let us know if anything changed or was deleted.
	if len(ebc.svcMap.Updated()) != 0 || len(ebc.svcMap.Deleted()) != 0 {
		ebc.Sync()
	}

	for _, ctx := range renderContexts {
		ctx.Finalize()
	}

	// check if we have changes to apply
	if !fullResync && !table4.Changed() && !table6.Changed() {
		klog.V(1).Info("no changes to apply")
		return
	}

	klog.V(1).Infof("nft rules generated (%s)", time.Since(start))

	// render the rule set
	//retry:
	cmdIn, pipeOut := io.Pipe()

	deferred := new(bytes.Buffer)
	go renderNftables(pipeOut, deferred)

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = cmdIn
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmdStart := time.Now()
	err := cmd.Run()
	cmdExecTime := time.Since(cmdStart)

	if err != nil {
		klog.Errorf("nft failed: %v (%s)", err, cmdExecTime)

		// ensure render is finished
		io.Copy(ioutil.Discard, cmdIn)

		if !fullResync {
			// failsafe: rebuild everything
			klog.Infof("doing a full resync after nft failure")
			fullResync = true
			//goto retry
		}
		return
	}

	klog.V(1).Infof("nft ok (%s)", cmdExecTime)

	if deferred.Len() != 0 {
		klog.V(1).Infof("running deferred nft actions")

		// too fast and deletes fail... :(
		//time.Sleep(100 * time.Millisecond)

		if klog.V(2).Enabled() {
			os.Stdout.Write(deferred.Bytes())
		}

		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = deferred
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err = cmd.Run()
		if err != nil {
			klog.Warning("nft deferred script failed: ", err)
		}
	}

	if fullResync {
		// all done, we can validate the first run
		fullResync = false
	}
}

// Sync will take the new internally cached state and apply it to the bpf maps
// fully syncing the maps on every iteration.
func (ebc *ebpfController) Sync() {

	for _, KV := range ebc.svcMap.Deleted() {
		svcInfo := KV.Value.(svcEndpointMapping)

		klog.Infof("Deleting ServicePort: %s", string(KV.Key))

		svcKeys, _, backendKeys, _ := makeEbpfMaps(svcInfo)

		if _, err := ebc.objs.V4SvcMap.BatchDelete(svcKeys, &cebpf.BatchOptions{}); err != nil {
			klog.Fatalf("Failed Deleting service entries: %v", err)
			ebc.Cleanup()
		}

		if _, err := ebc.objs.V4BackendMap.BatchDelete(backendKeys, &cebpf.BatchOptions{}); err != nil {
			klog.Fatalf("Failed Deleting service backend entries: %v", err)
			ebc.Cleanup()
		}

		// Remove service entry from cache
		ebc.svcMap.Delete(KV.Key)
	}

	for _, KV := range ebc.svcMap.Updated() {
		svcInfo := KV.Value.(svcEndpointMapping)

		klog.Infof("Adding ServicePort: %s", string(KV.Key))

		svcKeys, svcValues, backendKeys, backendValues := makeEbpfMaps(svcInfo)

		if _, err := ebc.objs.V4SvcMap.BatchUpdate(svcKeys, svcValues, &cebpf.BatchOptions{}); err != nil {
			klog.Fatalf("Failed Loading service entries: %v", err)
			ebc.Cleanup()
		}

		if _, err := ebc.objs.V4BackendMap.BatchUpdate(backendKeys, backendValues, &cebpf.BatchOptions{}); err != nil {
			klog.Fatalf("Failed Loading service backend entries: %v", err)
			ebc.Cleanup()
		}
	}
}

func makeEbpfMaps(svcMapping svcEndpointMapping) (svcKeys []bpfV4Key, svcValues []bpfLb4Service,
	backendKeys []uint32, backendValues []bpfLb4Backend) {
	var svcPort [2]byte
	var targetPort [2]byte
	var backendAddress [4]byte
	var ID uint32
	var err error
	addresses := []string{}

	// Encode Port in LE and then Load in NE to ensure the int value that's loaded
	// is in fact in Network Endian
	binary.BigEndian.PutUint16(targetPort[:], uint16(svcMapping.Svc.targetPort))
	binary.BigEndian.PutUint16(svcPort[:], uint16(svcMapping.Svc.port))

	for _, endpoint := range svcMapping.Endpoint {
		addresses = append(addresses, endpoint.IPs.V4...)
	}

	// Make root (backendID 0, count != # of backends) key/value for service
	svcKeys = append(svcKeys, bpfV4Key{
		// Load to map in network endian
		// net package automatically represents in NE, no need to convert
		Address:     binary.LittleEndian.Uint32(svcMapping.Svc.clusterIP.To4()),
		Dport:       binary.LittleEndian.Uint16(svcPort[:]),
		BackendSlot: 0,
	})

	svcValues = append(svcValues, bpfLb4Service{Count: uint16(len(addresses))})

	// Make rest of svc and backend entries for service
	for i, address := range addresses {
		i := i
		copy(backendAddress[:], net.ParseIP(address).To4())

		svcKeys = append(svcKeys, bpfV4Key{
			Address:     binary.LittleEndian.Uint32(svcMapping.Svc.clusterIP.To4()),
			Dport:       binary.LittleEndian.Uint16(svcPort[:]),
			BackendSlot: uint16(i + 1),
		})

		// Make backendID the int value of the string version of the address + int protocol value
		err = binary.Read(bytes.NewBuffer(net.ParseIP(address).To4()), binary.BigEndian, &ID)
		if err != nil {
			klog.Errorf("Failed to convert endpoint address: %s to Int32, err : %v",
				address, err)
		}
		// Increment by port to have unique backend value for each svcPort
		ID = ID + uint32(svcMapping.Svc.port)

		svcValues = append(svcValues, bpfLb4Service{
			Count:     0,
			BackendId: ID,
		})

		backendKeys = append(backendKeys, uint32(ID))

		backendValues = append(backendValues, bpfLb4Backend{
			Address: binary.LittleEndian.Uint32(net.ParseIP(address).To4()),
			Port:    binary.LittleEndian.Uint16(targetPort[:]),
		})
	}
	klog.V(5).Infof("Writing svcKeys %+v \nsvcValues %+v \nbackendKeys %+v \nbackendValues %+v",
		svcKeys, svcValues, backendKeys, backendValues)

	return svcKeys, svcValues, backendKeys, backendValues
}

func addDispatchChains(table *nftable) {
	dnatAll := table.Chains.Get("z_dnat_all")
	if *withTrace {
		dnatAll.WriteString("  meta nftrace set 1\n")
	}

	if table.Chains.Has("dnat_external") {
		fmt.Fprint(dnatAll, "  jump dnat_external\n")
	}

	if table.Chains.Has("nodeports_dnat") {
		dnatAll.WriteString("  fib daddr type local jump nodeports_dnat\n")
	}

	if dnatAll.Len() != 0 {
		for _, hook := range []string{"prerouting"} {
			fmt.Fprintf(table.Chains.Get("z_hook_nat_"+hook),
				"  type nat hook "+hook+" priority %d;\n  jump z_dnat_all\n", *hookPrio)
		}
	}

	// filtering
	filterAll := table.Chains.Get("z_filter_all")
	fmt.Fprint(filterAll, "  ct state invalid drop\n")

	if table.Chains.Has("filter_external") {
		fmt.Fprint(filterAll, "  jump filter_external\n")
	}

	if table.Chains.Has("nodeports_filter") {
		filterAll.WriteString("  fib daddr type local jump nodeports_filter\n")
	}

	fmt.Fprintf(table.Chains.Get("z_hook_filter_forward"),
		"  type filter hook forward priority %d;\n  jump z_filter_all\n", *hookPrio)
	fmt.Fprintf(table.Chains.Get("z_hook_filter_output"),
		"  type filter hook output priority %d;\n  jump z_filter_all\n", *hookPrio)
}

func addPostroutingChain(table *nftable, clusterCIDRs []string, localEndpointIPs []string) {
	hasCIDRs := len(clusterCIDRs) != 0
	hasLocalEPs := len(localEndpointIPs) != 0

	if !hasCIDRs && !hasLocalEPs {
		return
	}

	chain := table.Chains.Get("zz_hook_nat_postrouting")
	fmt.Fprintf(chain, "  type nat hook postrouting priority %d;\n", *hookPrio)
	if hasCIDRs {
		chain.Writeln()
		fmt.Fprint(chain, "  # masquerade non-cluster traffic to non-local endpoints\n")
		fmt.Fprint(chain, "  ", table.Family, " saddr != { ", strings.Join(clusterCIDRs, ", "), " } \\\n")
		if hasLocalEPs {
			fmt.Fprint(chain, "  ", table.Family, " daddr != { ", strings.Join(localEndpointIPs, ", "), " } \\\n")
		}
		fmt.Fprint(chain, "  fib daddr type != local \\\n")
		fmt.Fprint(chain, "  masquerade\n")
	}

	if hasLocalEPs {
		chain.Writeln()
		fmt.Fprint(chain, "  # masquerade hairpin traffic\n")
		chain.WriteString("  ")
		chain.WriteString(table.Family)
		chain.WriteString(" saddr . ")
		chain.WriteString(table.Family)
		chain.WriteString(" daddr { ")
		for i, ip := range localEndpointIPs {
			if i != 0 {
				chain.WriteString(", ")
			}
			chain.WriteString(ip + " . " + ip)
		}
		chain.WriteString(" } masquerade\n")
	}
}

func renderNftables(output io.WriteCloser, deferred io.Writer) {
	defer output.Close()

	outputs := make([]io.Writer, 0, 2)
	outputs = append(outputs, output)

	if klog.V(2).Enabled() {
		outputs = append(outputs, os.Stdout)
	}

	out := bufio.NewWriter(io.MultiWriter(outputs...))

	for _, table := range allTables {
		// flush/delete previous state
		if fullResync {
			fmt.Fprintf(out, "table %s %s\n", table.Family, table.Name)
			fmt.Fprintf(out, "delete table %s %s\n", table.Family, table.Name)

		} else {
			for _, ks := range table.KindStores() {
				// flush deleted elements
				for _, item := range ks.Store.Deleted() {
					fmt.Fprintf(out, "flush %s %s %s %s\n", ks.Kind, table.Family, table.Name, item.Key())
				}

				// flush changed elements
				for _, item := range ks.Store.Changed() {
					if item.Created() {
						continue
					}
					fmt.Fprintf(out, "flush %s %s %s %s\n", ks.Kind, table.Family, table.Name, item.Key())
				}
			}
		}

		// create/update changed elements
		fmt.Fprintf(out, "table %s %s {\n", table.Family, table.Name)
		for _, ki := range table.OrderedChanges(fullResync) {
			fmt.Fprintf(out, " %s %s {\n", ki.Kind, ki.Item.Key())
			io.Copy(out, ki.Item.Value())
			fmt.Fprintln(out, " }")
		}
		fmt.Fprintln(out, "}")

		// delete removed elements (already done by deleting the table on fullResync)
		if !fullResync {
			// delete
			if canDeleteChains {
				var out io.Writer = out
				if deferDelete {
					out = deferred
				}
				for _, ks := range table.KindStores() {
					for _, item := range ks.Store.Deleted() {
						fmt.Fprintf(out, "delete %s %s %s %s\n", ks.Kind, table.Family, table.Name, item.Key())
					}
				}
			}
		}
	}

	out.Flush()
}

// nftKey convert an expected key to the real key to write to nft. It should be the same but some nft versions have a bug.
func nftKey(x int) (y int) {
	return x
}