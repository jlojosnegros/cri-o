package runtimehandlerhooks

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jaypipes/ghw"
	ghwcpu "github.com/jaypipes/ghw/pkg/cpu"

	"github.com/cri-o/cri-o/internal/config/cgmgr"
	"github.com/cri-o/cri-o/internal/lib/sandbox"
	"github.com/cri-o/cri-o/internal/log"
	"github.com/cri-o/cri-o/internal/oci"
	crioannotations "github.com/cri-o/cri-o/pkg/annotations"
	"github.com/cri-o/cri-o/utils/cmdrunner"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/systemd"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"
)

const (
	// HighPerformance contains the high-performance runtime handler name
	HighPerformance = "high-performance"
	// IrqBannedCPUConfigFile contains the original banned cpu mask configuration
	IrqBannedCPUConfigFile = "/etc/sysconfig/orig_irq_banned_cpus"
	// IrqSmpAffinityProcFile contains the default smp affinity mask configuration
	IrqSmpAffinityProcFile = "/proc/irq/default_smp_affinity"
)

const (
	annotationTrue       = "true"
	annotationDisable    = "disable"
	schedDomainDir       = "/proc/sys/kernel/sched_domain"
	cgroupMountPoint     = "/sys/fs/cgroup"
	irqBalanceBannedCpus = "IRQBALANCE_BANNED_CPUS"
	irqBalancedName      = "irqbalance"
	systemCPUDir         = "/sys/devices/system/cpu"
)

// cpuOnlineStatus refer to the values to write to `online` file to change CPU status
type cpuOnlineStatus string

// Constants for valid cpuOnlineStasu:
const (
	ONLINE  cpuOnlineStatus = "1"
	OFFLINE cpuOnlineStatus = "0"
)

// HighPerformanceHooks used to run additional hooks that will configure a system for the latency sensitive workloads
type HighPerformanceHooks struct {
	irqBalanceConfigFile string
}

func (h *HighPerformanceHooks) PreStart(ctx context.Context, c *oci.Container, s *sandbox.Sandbox) error {
	log.Infof(ctx, "Run %q runtime handler pre-start hook for the container %q", HighPerformance, c.ID())

	if isCgroupParentBurstable(s) {
		log.Infof(ctx, "Container %q is a burstable pod. Skip PreStart.", c.ID())
		return nil
	}
	if isCgroupParentBestEffort(s) {
		log.Infof(ctx, "Container %q is a besteffort pod. Skip PreStart.", c.ID())
		return nil
	}
	if !isContainerRequestWholeCPU(c) {
		log.Infof(ctx, "Container %q requests partial cpu(s). Skip PreStart", c.ID())
		return nil
	}

	// disable the CPU load balancing for the container CPUs
	if shouldCPULoadBalancingBeDisabled(s.Annotations()) {
		log.Infof(ctx, "Disable cpu load balancing for container %q", c.ID())
		if err := setCPUSLoadBalancing(c, false, schedDomainDir); err != nil {
			return errors.Wrap(err, "set CPU load balancing")
		}
	}

	// disable the IRQ smp load balancing for the container CPUs
	if shouldIRQLoadBalancingBeDisabled(s.Annotations()) {
		log.Infof(ctx, "Disable irq smp balancing for container %q", c.ID())
		if err := setIRQLoadBalancing(c, false, IrqSmpAffinityProcFile, h.irqBalanceConfigFile); err != nil {
			return errors.Wrap(err, "set IRQ load balancing")
		}
	}

	// disable the CFS quota for the container CPUs
	if shouldCPUQuotaBeDisabled(s.Annotations()) {
		log.Infof(ctx, "Disable cpu cfs quota for container %q", c.ID())
		cpuMountPoint, err := cgroups.FindCgroupMountpoint(cgroupMountPoint, "cpu")
		if err != nil {
			return err
		}
		if err := setCPUQuota(cpuMountPoint, s.CgroupParent(), c, false); err != nil {
			return errors.Wrap(err, "set CPU CFS quota")
		}
	}

	if coresToKeep, ok := shouldHyperThreadingSiblingCoresBeDisabled(s.Annotations()); ok {
		log.Infof(ctx, "Disable HT cores for container %q keeping %d online for housekeeping", c.ID(), coresToKeep)
		err := setHTSiblingsOffline(c, systemCPUDir, coresToKeep)
		if err != nil {
			return errors.Wrap(err, "disable HT siblings")
		}
	}

	return nil
}

func (h *HighPerformanceHooks) PreStop(ctx context.Context, c *oci.Container, s *sandbox.Sandbox) error {
	log.Infof(ctx, "Run %q runtime handler pre-stop hook for the container %q", HighPerformance, c.ID())

	if isCgroupParentBurstable(s) {
		log.Infof(ctx, "Container %q is a burstable pod. Skip PreStop.", c.ID())
		return nil
	}
	if isCgroupParentBestEffort(s) {
		log.Infof(ctx, "Container %q is a besteffort pod. Skip PreStop.", c.ID())
		return nil
	}
	if !isContainerRequestWholeCPU(c) {
		log.Infof(ctx, "Container %q requests partial cpu(s). Skip PreStop", c.ID())
		return nil
	}

	// enable the CPU load balancing for the container CPUs
	if shouldCPULoadBalancingBeDisabled(s.Annotations()) {
		if err := setCPUSLoadBalancing(c, true, schedDomainDir); err != nil {
			return errors.Wrap(err, "set CPU load balancing")
		}
	}

	// enable the IRQ smp balancing for the container CPUs
	if shouldIRQLoadBalancingBeDisabled(s.Annotations()) {
		if err := setIRQLoadBalancing(c, true, IrqSmpAffinityProcFile, h.irqBalanceConfigFile); err != nil {
			return errors.Wrap(err, "set IRQ load balancing")
		}
	}

	// no need to reverse the cgroup CPU CFS quota setting as the pod cgroup will be deleted anyway

	if _, ok := shouldHyperThreadingSiblingCoresBeDisabled(s.Annotations()); ok {
		log.Infof(ctx, "Enable HT cores for container %q", c.ID())
		err := setAllHTSiblingsOnline(c, systemCPUDir)
		if err != nil {
			return errors.Wrap(err, "enable HT siblings")
		}
	}
	return nil
}

// Returns true if the container has  the annotation `crioannotations.NumSiblingCoresEnabled`.
// That means logical processors sibilngs to those assigned to the container
// could be set offline while the container is running
func shouldHyperThreadingSiblingCoresBeDisabled(annotations fields.Set) (uint, bool) {
	coresNumberStr, ok := annotations[crioannotations.NumSiblingCoresEnabled]
	if !ok {
		return 0, false
	}

	coresNumber, err := strconv.ParseUint(coresNumberStr, 10, 0)
	if err != nil {
		log.Warnf(context.TODO(), "Unable to get number of cores from %q: %v", coresNumberStr, err)
		return 0, false
	}
	return uint(coresNumber), true
}

func shouldCPULoadBalancingBeDisabled(annotations fields.Set) bool {
	if annotations[crioannotations.CPULoadBalancingAnnotation] == annotationTrue {
		log.Warnf(context.TODO(), annotationValueDeprecationWarning(crioannotations.CPULoadBalancingAnnotation))
	}

	return annotations[crioannotations.CPULoadBalancingAnnotation] == annotationTrue ||
		annotations[crioannotations.CPULoadBalancingAnnotation] == annotationDisable
}

func shouldCPUQuotaBeDisabled(annotations fields.Set) bool {
	if annotations[crioannotations.CPUQuotaAnnotation] == annotationTrue {
		log.Warnf(context.TODO(), annotationValueDeprecationWarning(crioannotations.CPUQuotaAnnotation))
	}

	return annotations[crioannotations.CPUQuotaAnnotation] == annotationTrue ||
		annotations[crioannotations.CPUQuotaAnnotation] == annotationDisable
}

func shouldIRQLoadBalancingBeDisabled(annotations fields.Set) bool {
	if annotations[crioannotations.IRQLoadBalancingAnnotation] == annotationTrue {
		log.Warnf(context.TODO(), annotationValueDeprecationWarning(crioannotations.IRQLoadBalancingAnnotation))
	}

	return annotations[crioannotations.IRQLoadBalancingAnnotation] == annotationTrue ||
		annotations[crioannotations.IRQLoadBalancingAnnotation] == annotationDisable
}

func annotationValueDeprecationWarning(annotation string) string {
	return fmt.Sprintf("The usage of the annotation %q with value %q will be deprecated under 1.21", annotation, "true")
}

func isCgroupParentBurstable(s *sandbox.Sandbox) bool {
	return strings.Contains(s.CgroupParent(), "burstable")
}

func isCgroupParentBestEffort(s *sandbox.Sandbox) bool {
	return strings.Contains(s.CgroupParent(), "besteffort")
}

func isContainerRequestWholeCPU(c *oci.Container) bool {
	return *(c.Spec().Linux.Resources.CPU.Shares)%1024 == 0
}

// Look for all the cpu thread siblings of those assinged to Container
// and disable (set offline) as much of them as possible ensuring:
// - At least the number of `coresToKeep` are left online.
// - Never disable all the siblings of the same core.
//
// warn: if a container has assigned two cpus that are siblings it could end
//      running with less cpus than requested.
func setHTSiblingsOffline(c *oci.Container, systemCPUDIR string, coresToKeep uint) error {
	cpus, err := getContainerCPUList(c)
	if err != nil {
		return err
	}

	containerLogicalProcessors, err := cpuset.Parse(cpus)
	if err != nil {
		return err
	}

	if coresToKeep >= uint(containerLogicalProcessors.Size()) {
		return nil
	}

	nodeCPUInfo, err := ghw.CPU()
	if err != nil {
		return err
	}

	toDisable := make(map[int]struct{})
	for _, containerLogicalProcessorID := range containerLogicalProcessors.ToSlice() {
		if containerLogicalProcessorID == 0 {
			// on some architectures diabling CPU0 could end in a system brick
			// so avoid it.
			continue
		}
		// If the cpuID is already in the set of cpus to be disabled
		// we do NOT keep looking for siblings to disable.
		// This handles the case when a container has two sibling cpus assigned
		// so we do not disable both of them
		if _, ok := toDisable[containerLogicalProcessorID]; ok {
			continue
		}
		toadd := findLogicalProcessorSiblings(nodeCPUInfo, containerLogicalProcessorID)
		for x := range toadd {
			toDisable[x] = struct{}{}
		}
	}

	td := make([]int, 0, len(toDisable))
	for x := range toDisable {
		td = append(td, x)
	}

	numberOfLogicalProcessorsToDisable := uint(containerLogicalProcessors.Size()) - coresToKeep
	for idx := 0; idx < len(td) && idx < int(numberOfLogicalProcessorsToDisable); idx++ {
		if err := changeLogicalProcessorOnlineStatus(systemCPUDIR, OFFLINE, td[idx]); err != nil {
			return err
		}
	}

	return nil
}

// Look for all the cpu thread siblings of those assinged to Container
// and enable (set online) all of them.
//
// This function restablish those cpus disabled by `setHTSiblingsOffline`
func setAllHTSiblingsOnline(c *oci.Container, systemCPUDIR string) error {
	cpus, err := getContainerCPUList(c)
	if err != nil {
		return err
	}

	containerLogicalProcessors, err := cpuset.Parse(cpus)
	if err != nil {
		return err
	}

	nodeCPUInfo, err := ghw.CPU()
	if err != nil {
		return err
	}

	toEnable := cpuset.NewBuilder()
	for _, containerLogicalProcessorID := range containerLogicalProcessors.ToSlice() {
		toEnable.Add(findLogicalProcessorSiblings(nodeCPUInfo, containerLogicalProcessorID)...)
	}

	for _, logicalProcessorID := range toEnable.Result().ToSlice() {
		if err := changeLogicalProcessorOnlineStatus(systemCPUDIR, ONLINE, logicalProcessorID); err != nil {
			return err
		}
	}

	return nil
}

// Change the online/offline status of a CPU identified by `id` writing to
// `<systemCPUDir>/cpu<id>/online system file.
func changeLogicalProcessorOnlineStatus(systemCPUDir string, value cpuOnlineStatus, id int) error {
	onlineFileName := filepath.Join(systemCPUDir, fmt.Sprintf("cpu%d", id), "online")

	// jlom: Not sure all this is needed
	fileInfo, err := os.Stat(onlineFileName)
	if err != nil {
		return err
	}

	if !fileInfo.Mode().IsRegular() {
		return fmt.Errorf("non-regular file")
	}

	err = ioutil.WriteFile(onlineFileName, []byte(value), fileInfo.Mode().Perm())
	if err != nil {
		return err
	}

	return nil
}

// Find all the logical processors siblings with the one identified by `logicalProcessorID`.
//
// note: siblings in this context means all non harware CPUS in the same core that share L1 cache
func findLogicalProcessorSiblings(cpuInfo *ghwcpu.Info, logicalProcessorID int) []int {
	for _, processor := range cpuInfo.Processors {
		for _, core := range processor.Cores {
			found := -1

			for idx, id := range core.LogicalProcessors {
				if id == logicalProcessorID {
					found = idx
					break
				}
			}
			if found >= 0 {
				var ret []int
				ret = append(ret, core.LogicalProcessors[:found]...)
				return append(ret, core.LogicalProcessors[found+1:]...)
			}
		}
	}
	return []int{}
}

func getContainerCPUList(c *oci.Container) (string, error) {
	lspec := c.Spec().Linux
	if lspec == nil ||
		lspec.Resources == nil ||
		lspec.Resources.CPU == nil ||
		lspec.Resources.CPU.Cpus == "" {
		return "", errors.Errorf("find container %s CPUs", c.ID())
	}

	return lspec.Resources.CPU.Cpus, nil
}

func setCPUSLoadBalancing(c *oci.Container, enable bool, schedDomainDir string) error {
	lspec := c.Spec().Linux
	if lspec == nil ||
		lspec.Resources == nil ||
		lspec.Resources.CPU == nil ||
		lspec.Resources.CPU.Cpus == "" {
		return errors.Errorf("find container %s CPUs", c.ID())
	}

	cpus, err := cpuset.Parse(lspec.Resources.CPU.Cpus)
	if err != nil {
		return err
	}

	for _, cpu := range cpus.ToSlice() {
		cpuSchedDomainDir := fmt.Sprintf("%s/cpu%d", schedDomainDir, cpu)
		err := filepath.Walk(cpuSchedDomainDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() || info.Name() != "flags" {
				return nil
			}
			content, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			flags, err := strconv.Atoi(strings.Trim(string(content), "\n"))
			if err != nil {
				return err
			}

			var newContent string
			if enable {
				newContent = strconv.Itoa(flags | 1)
			} else {
				// we should set the LSB to 0 to disable the load balancing for the specified CPU
				// in case of sched domain all flags can be represented by the binary number 111111111111111 that equals
				// to 32767 in the decimal form
				// see https://github.com/torvalds/linux/blob/0fe5f9ca223573167c4c4156903d751d2c8e160e/include/linux/sched/topology.h#L14
				// for more information regarding the sched domain flags
				newContent = strconv.Itoa(flags & 32766)
			}

			return ioutil.WriteFile(path, []byte(newContent), 0o644)
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func setIRQLoadBalancing(c *oci.Container, enable bool, irqSmpAffinityFile, irqBalanceConfigFile string) error {
	lspec := c.Spec().Linux
	if lspec == nil ||
		lspec.Resources == nil ||
		lspec.Resources.CPU == nil ||
		lspec.Resources.CPU.Cpus == "" {
		return errors.Errorf("find container %s CPUs", c.ID())
	}

	content, err := ioutil.ReadFile(irqSmpAffinityFile)
	if err != nil {
		return err
	}
	currentIRQSMPSetting := strings.TrimSpace(string(content))
	newIRQSMPSetting, newIRQBalanceSetting, err := UpdateIRQSmpAffinityMask(lspec.Resources.CPU.Cpus, currentIRQSMPSetting, enable)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(irqSmpAffinityFile, []byte(newIRQSMPSetting), 0o644); err != nil {
		return err
	}

	isIrqConfigExists := fileExists(irqBalanceConfigFile)

	if isIrqConfigExists {
		if err := updateIrqBalanceConfigFile(irqBalanceConfigFile, newIRQBalanceSetting); err != nil {
			return err
		}
	}

	if !isServiceEnabled(irqBalancedName) || !isIrqConfigExists {
		if _, err := exec.LookPath(irqBalancedName); err != nil {
			// irqbalance is not installed, skip the rest; pod should still start, so return nil instead
			logrus.Warnf("Irqbalance binary not found: %v", err)
			return nil
		}
		// run irqbalance in daemon mode, so this won't cause delay
		cmd := cmdrunner.Command(irqBalancedName, "--oneshot")
		additionalEnv := irqBalanceBannedCpus + "=" + newIRQBalanceSetting
		cmd.Env = append(os.Environ(), additionalEnv)
		return cmd.Run()
	}

	if err := restartIrqBalanceService(); err != nil {
		logrus.Warnf("Irqbalance service restart failed: %v", err)
	}
	return nil
}

func setCPUQuota(cpuMountPoint, parentDir string, c *oci.Container, enable bool) error {
	var rpath string
	var err error
	var cfsQuotaPath string
	var parentCfsQuotaPath string
	var cgroupManager cgmgr.CgroupManager

	if strings.HasSuffix(parentDir, ".slice") {
		// systemd fs
		if cgroupManager, err = cgmgr.SetCgroupManager("systemd"); err != nil {
			return nil
		}
		parentPath, err := systemd.ExpandSlice(parentDir)
		if err != nil {
			return err
		}
		parentCfsQuotaPath = filepath.Join(cpuMountPoint, parentPath, "cpu.cfs_quota_us")
		if rpath, err = cgroupManager.ContainerCgroupAbsolutePath(parentDir, c.ID()); err != nil {
			return err
		}
		cfsQuotaPath = filepath.Join(cpuMountPoint, rpath, "cpu.cfs_quota_us")
	} else {
		// cgroupfs
		if cgroupManager, err = cgmgr.SetCgroupManager("cgroupfs"); err != nil {
			return nil
		}
		parentCfsQuotaPath = filepath.Join(cpuMountPoint, parentDir, "cpu.cfs_quota_us")
		if rpath, err = cgroupManager.ContainerCgroupAbsolutePath(parentDir, c.ID()); err != nil {
			return err
		}
		cfsQuotaPath = filepath.Join(cpuMountPoint, rpath, "cpu.cfs_quota_us")
	}

	if _, err := os.Stat(cfsQuotaPath); err != nil {
		return err
	}
	if _, err := os.Stat(parentCfsQuotaPath); err != nil {
		return err
	}

	if enable {
		// there should have no use case to get here, as the pod cgroup will be deleted when the pod end
		if err := ioutil.WriteFile(cfsQuotaPath, []byte("0"), 0o644); err != nil {
			return err
		}
		if err := ioutil.WriteFile(parentCfsQuotaPath, []byte("0"), 0o644); err != nil {
			return err
		}
	} else {
		if err := ioutil.WriteFile(cfsQuotaPath, []byte("-1"), 0o644); err != nil {
			return err
		}
		if err := ioutil.WriteFile(parentCfsQuotaPath, []byte("-1"), 0o644); err != nil {
			return err
		}
	}

	return nil
}

// RestoreIrqBalanceConfig restores irqbalance service with original banned cpu mask settings
func RestoreIrqBalanceConfig(irqBalanceConfigFile, irqBannedCPUConfigFile, irqSmpAffinityProcFile string) error {
	content, err := ioutil.ReadFile(irqSmpAffinityProcFile)
	if err != nil {
		return err
	}
	current := strings.TrimSpace(string(content))
	// remove ","; now each element is "0-9,a-f"
	s := strings.ReplaceAll(current, ",", "")
	currentMaskArray, err := mapHexCharToByte(s)
	if err != nil {
		return err
	}
	if !isAllBitSet(currentMaskArray) {
		// not system reboot scenario, just return it.
		return nil
	}

	bannedCPUMasks, err := retrieveIrqBannedCPUMasks(irqBalanceConfigFile)
	if err != nil {
		// Ignore returning err as given irqBalanceConfigFile may not exist.
		return nil
	}
	if !fileExists(irqBannedCPUConfigFile) {
		irqBannedCPUsConfig, err := os.Create(irqBannedCPUConfigFile)
		if err != nil {
			return err
		}
		defer irqBannedCPUsConfig.Close()
		_, err = irqBannedCPUsConfig.WriteString(bannedCPUMasks)
		if err != nil {
			return err
		}
		return nil
	}

	content, err = ioutil.ReadFile(irqBannedCPUConfigFile)
	if err != nil {
		return err
	}
	origBannedCPUMasks := strings.TrimSpace(string(content))

	if bannedCPUMasks == origBannedCPUMasks {
		return nil
	}
	if err := updateIrqBalanceConfigFile(irqBalanceConfigFile, origBannedCPUMasks); err != nil {
		return err
	}
	if isServiceEnabled(irqBalancedName) {
		if err := restartIrqBalanceService(); err != nil {
			logrus.Warnf("Irqbalance service restart failed: %v", err)
		}
	}
	return nil
}
