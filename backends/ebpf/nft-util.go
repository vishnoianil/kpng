/*
Copyright 2021 The Kubernetes Authors.

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
	"bytes"
	"errors"
	"os/exec"

	localv1 "sigs.k8s.io/kpng/api/localv1"

	"k8s.io/klog/v2"
)

func checkIPTableVersion() {
	cmdArr := [2]string{"ip6tables", "iptables"}
	for _, value := range cmdArr {
		cmd := exec.Command(value, "-V")
		stdout, err := cmd.Output()
		if err != nil && errors.Unwrap(err) != exec.ErrNotFound {
			klog.Warningf("cmd (%v) throws error: %v", cmd, err)
			continue
		}
		if bytes.Contains(stdout, []byte("legacy")) {
			klog.Warning("legacy ", value, " found")
		}
	}
}

func protoMatch(protocol localv1.Protocol) string {
	switch protocol {
	case localv1.Protocol_TCP:
		return "tcp dport"
	case localv1.Protocol_UDP:
		return "udp dport"
	case localv1.Protocol_SCTP:
		return "sctp dport"
	default:
		klog.Errorf("unknown protocol: %v", protocol)
		return ""
	}
}
