//go:build windows

package bridge

import (
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var (
	advapi32            = syscall.NewLazyDLL("advapi32.dll")
	ntdll               = syscall.NewLazyDLL("ntdll.dll")
	procNtFsControlFile = ntdll.NewProc("NtFsControlFile")
)

const (
	GLOBAL_RDR_DEVICE_NAME      = `\\?\GLOBALROOT\Device\LanmanRedirector`
	GLOBAL_VMSMB_DEVICE_NAME    = `\\?\GLOBALROOT\Device\vmsmb`
	GLOBAL_VMSMB_INSTANCE_NAME  = `\Device\vmsmb`
	GLOBAL_VMBUS_TRANSPORT_NAME = `\Device\VMBus\{4d12e519-17a0-4ae4-8eaa-5270fc6abdb7}-{dcc079ae-60ba-4d07-847c-3493609c0870}-0000`

	SE_LOAD_DRIVER_NAME = "SeLoadDriverPrivilege"

	FSCTL_LMR_START_INSTANCE    = 0x001403A0
	FSCTL_LMR_BIND_TO_TRANSPORT = 0x001401B0

	LMR_INSTANCE_FLAG_REGISTER_FILESYSTEM      = 0x2
	LMR_INSTANCE_FLAG_USE_CUSTOM_TRANSPORTS    = 0x4
	LMR_INSTANCE_FLAG_ALLOW_GUEST_AUTH         = 0x8
	LMR_INSTANCE_FLAG_SUPPORTS_DIRECTMAPPED_IO = 0x10

	SmbCeTransportTypeVmbus = 3
)

type IOStatusBlock struct {
	Status      uintptr
	Information uintptr
}

func configureAndStartLanmanWorkstation() error {
	m, err := mgr.Connect()
	if err != nil {
		logrus.Errorf("Failed to connect to Service Manager: %v", err)
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService("LanmanWorkstation")
	if err != nil {
		logrus.Errorf("Failed to open LanmanWorkstation service: %v", err)
		return err
	}
	defer s.Close()

	cmd := exec.Command("sc", "config", "LanmanWorkstation", "start=", "auto")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logrus.Errorf("Failed to set LanmanWorkstation start type: %v\nOutput: %s", err, string(output))
		return err
	}

	cmd = exec.Command("sc", "start", "LanmanWorkstation")
	output, err = cmd.CombinedOutput()
	if err != nil {
		logrus.Errorf("Failed to start LanmanWorkstation: %v\nOutput: %s", err, string(output))
		return err
	}
	return nil
}

func enablePrivilege(privName string) error {
	logrus.Printf("Enabling privilege: %s\n", privName)

	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		logrus.Errorf("OpenProcessToken failed: %v", err)
		return err
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, syscall.StringToUTF16Ptr(privName), &luid)
	if err != nil {
		logrus.Errorf("LookupPrivilegeValue failed: %v", err)
		return err
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}

	err = windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
	if err != nil {
		logrus.Errorf("AdjustTokenPrivileges failed: %v", err)
		return err
	}

	if windows.GetLastError() == windows.ERROR_SUCCESS {
		logrus.Println("Privilege enabled successfully.")
	} else {
		logrus.Errorf("AdjustTokenPrivileges warning: %v\n", windows.GetLastError())
	}

	return nil
}

func NtFsControlFile(handle syscall.Handle, fsctlCode uint32, inputBuffer []byte) (uint32, error) {
	var iosb IOStatusBlock

	r1, _, e1 := syscall.SyscallN(
		procNtFsControlFile.Addr(),
		uintptr(handle),
		0, 0, 0,
		uintptr(unsafe.Pointer(&iosb)),
		uintptr(fsctlCode),
		uintptr(unsafe.Pointer(&inputBuffer[0])),
		uintptr(len(inputBuffer)),
		0,
		0,
	)

	return uint32(r1), e1
}

// Structs
type SMB2InstanceConfiguration struct {
	DormantDirectoryTimeout             uint32
	DormantFileTimeout                  uint32
	DormantFileLimit                    uint32
	FileInfoCacheLifetime               uint32
	FileNotFoundCacheLifetime           uint32
	DirectoryCacheLifetime              uint32
	FileInfoCacheEntriesMax             uint32
	FileNotFoundCacheEntriesMax         uint32
	DirectoryCacheEntriesMax            uint32
	DirectoryCacheSizeMax               uint32
	ReadAheadGranularity                uint32
	VolumeFeatureSupportCacheLifetime   uint32
	VolumeFeatureSupportCacheEntriesMax uint32
	FileAbeStatusCacheLifetime          uint32
	RequireSecuritySignature            byte
	RequireEncryption                   byte
	Padding                             [2]byte
}

type LMRConnectionProperties struct {
	Flags1                          byte
	Flags2                          byte
	Padding                         [2]byte
	SessionTimeoutInterval          uint32
	CAHandleKeepaliveInterval       uint32
	NonCAHandleKeepaliveInterval    uint32
	ActiveIOKeepaliveInterval       uint32
	DisableRdma                     uint32
	ConnectionCountPerRdmaInterface uint32
	AlternateTcpPort                uint16
	AlternateQuicPort               uint16
	AlternateRdmaPort               uint16
	Padding2                        [2]byte
}

type LMRStartInstanceRequest struct {
	StructureSize               uint32
	IoTimeout                   uint32
	IoRetryCount                uint32
	Flags                       uint16
	Padding1                    uint16
	Reserved1                   uint32
	InstanceConfig              SMB2InstanceConfiguration
	DefaultConnectionProperties LMRConnectionProperties
	InstanceId                  byte
	Reserved2                   byte
	DeviceNameLength            uint16
}

type LMRBindUnbindTransportRequest struct {
	StructureSize     uint16
	Flags             uint16
	Type              uint32
	TransportIdLength uint32
}

func isLanmanWorkstationRunning() (bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer m.Disconnect()

	s, err := m.OpenService("LanmanWorkstation")
	if err != nil {
		return false, err
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return false, err
	}

	// Check if the service state is running
	return status.State == svc.Running, nil
}

func VsmbMain() {
	logrus.Info("Starting VSMB initialization...")

	logrus.Debug("Configuring LanmanWorkstation service...")
	if err := configureAndStartLanmanWorkstation(); err != nil {
		logrus.Errorf("LanmanWorkstation setup failed: %v", err)
		return
	}

	time.Sleep(3 * time.Second) // TODO: This needs to be better logic.
	running, err := isLanmanWorkstationRunning()
	if err != nil {
		logrus.Errorf("Failed to query LanmanWorkstation status: %v", err)
	} else if running {
		logrus.Info("LanmanWorkstation service is running.")
	} else {
		logrus.Warn("LanmanWorkstation service is NOT running.")
	}

	if err := enablePrivilege(SE_LOAD_DRIVER_NAME); err != nil {
		logrus.Errorf("Failed to enable privilege: %v", err)
		return
	}

	// Open LanmanRedirector
	lmrHandle, err := windows.CreateFile(
		syscall.StringToUTF16Ptr(GLOBAL_RDR_DEVICE_NAME),
		windows.SYNCHRONIZE|windows.FILE_LIST_DIRECTORY|windows.FILE_TRAVERSE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, 0, 0,
	)
	if err != nil {
		logrus.Errorf("Failed to open redirector: %v", err)
		return
	}
	defer windows.CloseHandle(lmrHandle)

	logrus.Info("Successfully opened LanmanRedirector device.")

	// Build StartInstance buffer
	instanceNameUTF16 := syscall.StringToUTF16(GLOBAL_VMSMB_INSTANCE_NAME)
	structSize := int(unsafe.Sizeof(LMRStartInstanceRequest{}))
	bufferSize := structSize + (len(instanceNameUTF16)-1)*2
	buffer := make([]byte, bufferSize)

	startReq := LMRStartInstanceRequest{
		StructureSize: uint32(structSize),
		IoTimeout:     30,
		IoRetryCount:  3,
		Flags: LMR_INSTANCE_FLAG_REGISTER_FILESYSTEM |
			LMR_INSTANCE_FLAG_USE_CUSTOM_TRANSPORTS |
			LMR_INSTANCE_FLAG_ALLOW_GUEST_AUTH |
			LMR_INSTANCE_FLAG_SUPPORTS_DIRECTMAPPED_IO,
		InstanceId:       1,
		DeviceNameLength: uint16((len(instanceNameUTF16) - 1) * 2),
	}

	startReq.Reserved1 = 0
	startReq.InstanceConfig = SMB2InstanceConfiguration{}
	startReq.DefaultConnectionProperties = LMRConnectionProperties{}
	startReq.DefaultConnectionProperties.Flags1 = 0x1F
	startReq.DefaultConnectionProperties.SessionTimeoutInterval = 55
	startReq.DefaultConnectionProperties.CAHandleKeepaliveInterval = 10
	startReq.DefaultConnectionProperties.NonCAHandleKeepaliveInterval = 30
	startReq.DefaultConnectionProperties.ActiveIOKeepaliveInterval = 30

	copy(buffer[:structSize], (*[1 << 20]byte)(unsafe.Pointer(&startReq))[:structSize])
	copy(buffer[structSize:], (*[1 << 20]byte)(unsafe.Pointer(&instanceNameUTF16[0]))[:(len(instanceNameUTF16)-1)*2])

	status, _ := NtFsControlFile(syscall.Handle(lmrHandle), FSCTL_LMR_START_INSTANCE, buffer)
	if status == 0 {
		logrus.Info("VMSMB RDR instance started.")
	} else if status == 0xC0000035 {
		logrus.Warn("VMSMB RDR instance already started.")
	} else {
		logrus.Errorf("NtFsControlFile failed: 0x%08X", status)
	}

	// BindTransport
	vmsmbHandle, err := windows.CreateFile(
		syscall.StringToUTF16Ptr(GLOBAL_VMSMB_DEVICE_NAME),
		windows.SYNCHRONIZE|windows.FILE_LIST_DIRECTORY|windows.FILE_TRAVERSE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, 0, 0,
	)
	if err != nil {
		logrus.Errorf("Failed to open VMSMB device: %v", err)
		return
	}
	defer windows.CloseHandle(vmsmbHandle)

	transportNameUTF16 := syscall.StringToUTF16(GLOBAL_VMBUS_TRANSPORT_NAME)
	bindStructSize := int(unsafe.Sizeof(LMRBindUnbindTransportRequest{}))
	bindBufferSize := bindStructSize + (len(transportNameUTF16)-1)*2
	bindBuffer := make([]byte, bindBufferSize)

	bindReq := LMRBindUnbindTransportRequest{
		StructureSize:     uint16(bindStructSize) + 4,
		Flags:             0,
		Type:              2,
		TransportIdLength: uint32((len(transportNameUTF16) - 1) * 2),
	}

	copy(bindBuffer[:bindStructSize], (*[1 << 20]byte)(unsafe.Pointer(&bindReq))[:bindStructSize])
	copy(bindBuffer[bindStructSize:], (*[1 << 20]byte)(unsafe.Pointer(&transportNameUTF16[0]))[:(len(transportNameUTF16)-1)*2])

	status, _ = NtFsControlFile(syscall.Handle(vmsmbHandle), FSCTL_LMR_BIND_TO_TRANSPORT, bindBuffer)
	if status == 0 {
		logrus.Info("VMBUS transport bound to VMSMB RDR instance.")
	} else {
		logrus.Errorf("NtFsControlFile failed: 0x%08X", status)
	}
}
