//! Enumerations for standardizing and categorizing types for SCOs.
//! Enumerations for standardizing and categorizing types for SCOs.
use serde::{Deserialize, Serialize};
use strum::{AsRefStr, EnumIter};

///The encryption algorithm enumeration
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum EncryptionAlgorithm {
    AES256GCM,
    ChaCha20Poly1305,
    MimeTypeIndicated,
}

/// The Windows registry datatype enumeration
/// The Windows registry datatype enumeration
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter, Serialize, Deserialize)]
pub enum WindowsRegistryDataTypeEnum {
    #[strum(serialize = "")]
    Default,
    #[strum(serialize = "REG_NONE")]
    RegNone,
    #[strum(serialize = "REG_SZ")]
    RegSz,
    #[strum(serialize = "REG_EXPAND_SZ")]
    RegExpandSz,
    #[strum(serialize = "REG_BINARY")]
    RegBinary,
    #[strum(serialize = "Reg_DWORD")]
    REGDword,
    #[strum(serialize = "REG_DWORD_BIG_ENDIAN")]
    RegDwordBigEndian,
    #[strum(serialize = "REG_DWORD_LITTLE_ENDIAN")]
    RegDwordLittleEndian,
    #[strum(serialize = "REG_LINK")]
    RegLink,
    #[strum(serialize = "REG_MULTI_SZ")]
    RegMultiSz,
    #[strum(serialize = "REG_RESOURCE_LIST")]
    RegResourceList,
    #[strum(serialize = "REG_FULL_RESOURCE_DESCRIPTION")]
    RegFullResourceDescription,
    #[strum(serialize = "REG_RESOURCEL_REQUIREMENTS_LIST")]
    RegResourceRequirementsList,
    #[strum(serialize = "REG_QWORD")]
    RegQword,
    #[strum(serialize = "REG_INVALID_TYPE")]
    RegInvalidType,
}

/// Represents the different types and functions of malware within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum AccountTypeVocabulary {
    Facebook,      //Specifies a Facebook account.
    Ldap,          //Specifies an LDAP account.
    Nis,           //Specifies a NIS account
    Openid,        //Specifies an OpenID account.
    Radius,        // Specifies a RADIUS account.
    Skype,         // Specifies a Skype account.
    Tacacs,        //Specifies a TACACS account.
    Twitter,       //Specifies a Twitter account.
    Unix,          //Specifies a POSIX account.
    WindowsLocal,  //Specifies a Windows local account.
    WindowsDomain, //Specifies a Windows domain account.
}

/// The Windows service start type enumeration
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter, Serialize, Deserialize)]
pub enum WindowsServiceStartTypeEnum {
    #[strum(serialize = "SERVICE_AUTO_START")]
    /// A service started automatically by the service control manager during system startup.
    ServiceAutoStart,

    #[strum(serialize = "SERVICE_BOOT_START")]
    ///A device driver started by the system loader. This value is valid only for driver services.
    ServiceBootStart,

    #[strum(serialize = "SERVICE_DEMAND_START")]
    /// A service started by the service control manager when a process calls the StartService function.
    ServiceDemandStart,

    #[strum(serialize = "SERVICE_DISABLED")]
    /// A service that cannot be started. Attempts to start the service result in the error code ERROR_SERVICE_DISABLED.
    ServiceDisabled,

    #[strum(serialize = "SERVICE_SYSTEM_ALERT")]
    ///  A device driver started by the IoInitSystem function. This value is valid only for driver services.
    ServiceSystemAlert,
}

/// The Windows service type enumeration
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter, Serialize, Deserialize)]
pub enum WindowsServiceTypeEnum {
    // Serialize preserves snake case
    #[strum(serialize = "SERVICE_KERNEL_DRIVER")]
    /// The service is a device driver.
    ServiceKernelDriver,

    #[strum(serialize = "SERVICE_FILE_SYSTEM_DRIVER")]
    /// The service is a file system driver.
    ServiceFileSystemDriver,

    #[strum(serialize = "SERVICE_WIN32_OWN_PROCESS")]
    /// The service runs in its own process.
    ServiceWin32OwnProcess,

    #[strum(serialize = "SERVICE_WIN32_SHARE_PROCESS")]
    ///The service shares a process with other services.
    ServiceWin32ShareProcess,
}

/// The Windows service status enumeration
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter, Serialize, Deserialize)]
pub enum WindowsServiceStatusEnum {
    // Serialize preserves snake case
    /// The service continue is continue pending.
    #[strum(serialize = "SERVICE_CONTINUE_PENDING")]
    ServiceContinuePending,

    /// The service pause is pause pending.
    #[strum(serialize = "SERVICE_PAUSE_PENDING")]
    ServicePausePending,

    /// The service is paused.
    #[strum(serialize = "SERVICE_PAUSED")]
    ServicePaused,

    /// The service is running.
    #[strum(serialize = "SERVICE_RUNNING")]
    ServiceRunning,

    /// The service is starting.
    #[strum(serialize = "SERVICE_START_PENDING")]
    ServiceStartPending,

    /// The service is stopping.
    #[strum(serialize = "SERVICE_STOP_PENDING")]
    ServiceStopPending,

    /// The service is stopped.
    #[strum(serialize = "SERVICE_STOPPED")]
    ServiceStopped,
}

/// The Windows integrity level enumeration
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum WindowsIntegrityEnum {
    /// A low level of integrity.
    Low,
    /// A medium level of integrity.
    Medium,
    /// A high level of integrity.
    High,
    /// A system level of integrity.
    System,
}

/// Network Socket Address Family Enumeration
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter, Serialize, Deserialize)]
pub enum NetworkSocketAddressFamilyEnum {
    // Serialize preserves snake case
    /// Specifies an unspecified address family.
    #[strum(serialize = "AF_UNSPEC")]
    AfUnspec,
    /// Specifies the IPv4 address family.
    #[strum(serialize = "AF_INET")]
    AfInet,
    /// Specifies the IPX (Novell Internet Protocol) address family.
    #[strum(serialize = "AF_IPX")]
    AfIpx,
    /// Specifies the APPLETALK DDP address family.
    #[strum(serialize = "AF_APPLETALK")]
    AfAppletalk,
    /// Specifies the NETBIOS address family.
    #[strum(serialize = "AF_NETBIOS")]
    AfNetbios,
    /// Specifies the IPv6 address family.
    #[strum(serialize = "AF_INET6")]
    AfInet6,
    /// Specifies IRDA sockets.
    #[strum(serialize = "AF_IRDA")]
    AfIrda,
    /// Specifies BTH sockets.
    #[strum(serialize = "AF_BTH")]
    AfBth,
}

/// Network Socket Type Enumeration
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter, Serialize, Deserialize)]
pub enum NetworkSocketTypeEnum {
    // Serialize preserves snake case
    /// Specifies a pipe-like socket which operates over a connection with a particular remote socket and transmits data reliably as a stream of bytes.
    #[strum(serialize = "SOCK_STREAM")]
    SockStream,
    /// Specifies a socket in which individually-addressed packets are sent (datagram).
    #[strum(serialize = "SOCK_DGRAM")]
    SockDgram,
    /// Specifies raw sockets which allow new IP protocols to be implemented in user space. A raw socket receives or sends the raw datagram not including link level headers.
    #[strum(serialize = "SOCK_RAW")]
    SockRaw,
    /// Specifies a socket indicating a reliably-delivered message.
    #[strum(serialize = "SOCK_RDM")]
    SockRdm,
    /// Specifies a datagram congestion control protocol socket.
    #[strum(serialize = "SOCK_SEQPACKET")]
    SockSeqpacket,
}

/// Internet Assigned Numbers Authority enumeration
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum IanaServiceNamesEnum {
    Dhcp,
    Dns,
    Ftp,
    Http,
    Https,
    Imap,
    Imcp,
    Ip,
    Irc,
    Ldap,
    Nfs,
    Ntp,
    Pop3,
    Rdp,
    Rtsp,
    Sftp,
    Sip,
    Smtp,
    Snmp,
    Ssh,
    Tcp,
    Telnet,
    Tftp,
}
