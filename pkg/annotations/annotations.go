package annotations

import (
	"github.com/intel/goresctrl/pkg/rdt"
)

const (
	// UsernsMode is the user namespace mode to use
	UsernsModeAnnotation = "io.kubernetes.cri-o.userns-mode"

	// CgroupRW specifies mounting v2 cgroups as an rw filesystem.
	Cgroup2RWAnnotation = "io.kubernetes.cri-o.cgroup2-mount-hierarchy-rw"

	// UnifiedCgroupAnnotation specifies the unified configuration for cgroup v2
	UnifiedCgroupAnnotation = "io.kubernetes.cri-o.UnifiedCgroup"

	// SpoofedContainer indicates a container was spoofed in the runtime
	SpoofedContainer = "io.kubernetes.cri-o.Spoofed"

	// ShmSizeAnnotation is the K8S annotation used to set custom shm size
	ShmSizeAnnotation = "io.kubernetes.cri-o.ShmSize"

	// DevicesAnnotation is a set of devices to give to the container
	DevicesAnnotation = "io.kubernetes.cri-o.Devices"

	// CPULoadBalancingAnnotation indicates that load balancing should be disabled for CPUs used by the container
	CPULoadBalancingAnnotation = "cpu-load-balancing.crio.io"

	// CPUQuotaAnnotation indicates that CPU quota should be disabled for CPUs used by the container
	CPUQuotaAnnotation = "cpu-quota.crio.io"

	// IRQLoadBalancingAnnotation indicates that IRQ load balancing should be disabled for CPUs used by the container
	IRQLoadBalancingAnnotation = "irq-load-balancing.crio.io"

	// OCISeccompBPFHookAnnotation is the annotation used by the OCI seccomp BPF hook for tracing container syscalls
	OCISeccompBPFHookAnnotation = "io.containers.trace-syscall"

	// TrySkipVolumeSELinuxLabelAnnotation is the annotation used for optionally skipping relabeling a volume
	// with the specified SELinux label.  The relabeling will be skipped if the top layer is already labeled correctly.
	TrySkipVolumeSELinuxLabelAnnotation = "io.kubernetes.cri-o.TrySkipVolumeSELinuxLabel"

	// Number of secondary threads to keep enabled for housekeeping tasks
	NumSiblingCoresEnabled = "max-ht-enabled-cores.crio.io"
)

var AllAllowedAnnotations = []string{
	UsernsModeAnnotation,
	Cgroup2RWAnnotation,
	UnifiedCgroupAnnotation,
	ShmSizeAnnotation,
	DevicesAnnotation,
	CPULoadBalancingAnnotation,
	CPUQuotaAnnotation,
	IRQLoadBalancingAnnotation,
	OCISeccompBPFHookAnnotation,
	rdt.RdtContainerAnnotation,
	TrySkipVolumeSELinuxLabelAnnotation,
	NumSiblingCoresEnabled,
}
