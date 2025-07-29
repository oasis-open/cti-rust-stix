//! Enumerations for standardizing and categorizing types for SDOs.

use serde::{Deserialize, Serialize};
use strum::{AsRefStr, EnumIter};

/// Represents the different processor architectures within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum ArchitectureExecutionEnvs {
    /// Specifies the Alpha architecture.
    Alpha,
    /// Specifies the ARM architecture.
    Arm,
    /// Specifies the 64-bit IA (Itanium) architecture.
    Ia64,
    /// Specifies the MIPS architecture.
    Mips,
    /// Specifies the PowerPC architecture.
    PowerPC,
    /// Specifies the SPARC architecture.
    Sparc,
    /// Specifies the 32-bit x86 architecture.
    X86,
    /// Specifies the 64-bit x86 architecture.
    X86_64,
}

/// Represents attack motivations used in Intrusion Set and Threat Actor SDOs within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum AttackMotivation {
    // A non-hostile actor whose benevolent or harmless intent inadvertently causes harm.
    Accidental,
    // Being forced to act on someone else's behalf, often through intimidation or blackmail.
    Coercion,
    // A desire to assert superiority over someone or something else.
    Dominance,
    // A passion to express a set of ideas, beliefs, and values that may drive harmful acts.
    Ideology,
    // Seeking prestige or to become well known through some activity.
    Notoriety,
    // Seeking advantage over a competing organization, including a military organization.
    OrganizationalGain,
    // The desire to improve one’s own financial status.
    PersonalGain,
    // A desire to satisfy a strictly personal goal, including curiosity or thrill-seeking.
    PersonalSatisfaction,
    // A desire to avenge perceived wrongs through harmful actions.
    Revenge,
    // Acting without identifiable reason or purpose, creating unpredictable events.
    Unpredictable,
}

/// Represents the resource levels available to threat actors within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum AttackResourceLevel {
    // Resources limited to the average individual; Threat Actor acts independently.
    Individual,
    // Members interact on a social and volunteer basis, often with little personal interest in the specific target.
    Club,
    // A short-lived interaction that concludes when participants achieve a single goal.
    Contest,
    // A formally organized group with a leader, motivated by a specific goal.
    Team,
    // Larger and better resourced than a team; typically a company or crime syndicate.
    Organization,
    // Controls public assets and functions within a jurisdiction; very well resourced.
    Government,
}

/// Represents different types of contexts within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter, Default)]
#[strum(serialize_all = "kebab-case")]
pub enum ContextType {
    SuspiciousActivity,
    MalwareAnalysis,
    #[default]
    Unspecified,
}

/// Represents various identity sectors within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum IdentitySectors {
    Agriculture,
    Aerospace,
    Automotive,
    Communications,
    Construction,
    Defence,
    Education,
    Energy,
    Entertainment,
    FinancialServices,
    GovernmentNational,
    GovernmentRegional,
    GovernmentLocal,
    GovernmentPublicServices,
    EmergencyServicesSanitation,
    Healthcare,
    HospitalityLeisure,
    Infrastructure,
    Insurance,
    Manufacturing,
    Mining,
    NonProfit,
    Pharmaceuticals,
    Retail,
    Technology,
    Telecommunications,
    Transportation,
    Utilities,
}

/// Represents different programming languages within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum ImplementationLanguage {
    /// Specifies the AppleScript programming language.
    AppleScript,
    /// Specifies the Bash Implementation language.
    Bash,
    /// Specifies the C Implementation language.
    C,
    /// Specifies the C++ Implementation language.
    CPlusPlus,
    /// Specifies the C# Implementation language.
    CSharp,
    /// Specifies the Go Implementation language.
    Go,
    /// Specifies the Java Implementation language.
    Java,
    /// Specifies the JavaScript Implementation language.
    JavaScript,
    /// Specifies the Lua Implementation language.
    Lua,
    /// Specifies the Objective-C Implementation language.
    ObjectiveC,
    /// Specifies the Perl Implementation language.
    Perl,
    /// Specifies the PHP Implementation language.
    Php,
    /// Specifies the Windows PowerShell Implementation language.
    PowerShell,
    /// Specifies the Python Implementation language.
    Python,
    /// Specifies the Ruby Implementation language.
    Ruby,
    /// Specifies the Scala Implementation language.
    Scala,
    /// Specifies the Swift Implementation language.
    Swift,
    /// Specifies the TypeScript Implementation language.
    TypeScript,
    /// Specifies the Visual Basic Implementation language.
    VisualBasic,
    /// Specifies the x86 32-bit Assembly Implementation language.
    X86_32,
    /// Specifies the x86 64-bit Assembly Implementation language.
    X86_64,
}

/// This is a non-exhaustive, open vocabulary that covers common pattern languages and is intended to characterize the pattern language that the indicator pattern is
/// expressed in within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum IndicatorPatternType {
    Pcre,
    Sigma,
    Snort,
    Suricata,
    Stix,
    Yara,
}

///Indicator type is an open vocabulary used to categorize Indicators.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum IndicatorType {
    AnomalousActivity,
    Anonymization,
    Benign,
    Compromised,
    MaliciousActivity,
    Attribution,
    Unknown,
}

/// Represents the type of infrastructure used in cyber attacks within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum InfrastructureType {
    /// Specifies infrastructure used for conducting amplification attacks.
    Amplification,
    /// Specific infrastructure used for anonymization, such as a proxy.
    Anonymization,
    /// Specifies the membership/makeup of a botnet, in terms of the network addresses of the hosts that comprise the botnet.
    Botnet,
    /// Specifies infrastructure used for command and control (C2). This is typically a domain name or IP address.
    CommandAndControl,
    /// Specifies infrastructure used as an endpoint for data exfiltration.
    Exfiltration,
    /// Specifies infrastructure used for hosting malware.
    HostingMalware,
    /// Specifies infrastructure used for hosting a list of targets for DDOS attacks, phishing, and other malicious activities. This is typically a domain name or IP address.
    HostingTargetLists,
    /// Specifies infrastructure used for conducting phishing attacks.
    Phishing,
    /// Specifies infrastructure used for conducting reconnaissance activities.
    Reconnaissance,
    /// Specifies infrastructure used for staging.
    Staging,
    /// Specifies an infrastructure of some undefined type.
    Undefined,
}

/// Represents different malware capabilities within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum MalwareCapability {
    /// Indicates the ability to access remote machines.
    AccessesRemoteMachines,
    /// Indicates the ability to prevent debugging or make it more difficult.
    AntiDebugging,
    /// Indicates the ability to prevent disassembly or make it more difficult.
    AntiDisassembly,
    /// Indicates the ability to prevent execution inside an emulator or make it more difficult.
    AntiEmulation,
    /// Indicates the ability to prevent or complicate memory forensics.
    AntiMemoryForensics,
    /// Indicates the ability to prevent sandbox-based analysis or make it more difficult.
    AntiSandbox,
    /// Indicates the ability to prevent VM-based analysis or make it more difficult.
    AntiVm,
    /// Indicates the ability to capture data from input peripherals, like keylogging.
    CapturesInputPeripherals,
    /// Indicates the ability to capture data from output peripherals, like screen scraping.
    CapturesOutputPeripherals,
    /// Indicates the ability to capture information about a system's state.
    CapturesSystemStateData,
    /// Indicates the ability to clean traces of infection from a system.
    CleansTracesOfInfection,
    /// Indicates the ability to commit fraud, such as click fraud.
    CommitsFraud,
    /// Indicates the ability to communicate with a command and control server.
    CommunicatesWithC2,
    /// Indicates the ability to compromise data availability.
    CompromisesDataAvailability,
    /// Indicates the ability to compromise data integrity.
    CompromisesDataIntegrity,
    /// Indicates the ability to consume system resources, compromising availability.
    CompromisesSystemAvailability,
    /// Indicates the ability to control the local machine.
    ControlsLocalMachine,
    /// Indicates the ability to bypass or disable security software.
    DegradesSecuritySoftware,
    /// Indicates the ability to disable system updates and patches.
    DegradesSystemUpdates,
    /// Indicates the ability to identify command and control servers.
    DeterminesC2Server,
    /// Indicates the ability to send spam email messages.
    EmailsSpam,
    /// Indicates the ability to escalate privileges.
    EscalatesPrivileges,
    /// Indicates the ability to evade antivirus detection.
    EvadesAv,
    /// Indicates the ability to exfiltrate data.
    ExfiltratesData,
    /// Indicates the ability to fingerprint the host system.
    FingerprintsHost,
    /// Indicates the ability to hide artifacts like files and open ports.
    HidesArtifacts,
    /// Indicates the ability to hide executing code.
    HidesExecutingCode,
    /// Indicates the ability to infect files on the system.
    InfectsFiles,
    /// Indicates the ability to infect remote machines.
    InfectsRemoteMachines,
    /// Indicates the ability to install additional components.
    InstallsOtherComponents,
    /// Indicates the ability to persist after a system reboot.
    PersistsAfterSystemReboot,
    /// Indicates the ability to prevent access to its artifacts.
    PreventsArtifactAccess,
    /// Indicates the ability to prevent deletion of its artifacts.
    PreventsArtifactDeletion,
    /// Indicates the ability to probe the network environment.
    ProbesNetworkEnvironment,
    /// Indicates the ability to modify itself.
    SelfModifies,
    /// Indicates the ability to steal authentication credentials.
    StealsAuthenticationCredentials,
    /// Indicates the ability to compromise system operational integrity.
    ViolatesSystemOperationalIntegrity,
}

/// Represents the common types of results from scanner or tool analysis process  within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum MalwareResult {
    Benign,
    Malicious,
    Suspicious,
    Unknown,
}

/// Represents the different types and functions of malware within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum MalwareType {
    /// Adware: Software funded by advertising, may gather sensitive user information.
    Adware,
    /// Backdoor: Allows an attacker to perform actions on a remote system.
    Backdoor,
    /// Bot: Resides on an infected system, part of a botnet, monitors a backdoor for instructions.
    Bot,
    /// Bootkit: Targets the Master Boot Record of the target computer.
    Bootkit,
    /// DDoS: Used to perform a distributed denial of service attack.
    Ddos,
    /// Downloader: A small trojan file programmed to download and execute other files.
    Downloader,
    /// Dropper: Deposits an enclosed payload (generally, other malware) onto the target computer.
    Dropper,
    /// ExploitKit: A software toolkit to target common vulnerabilities.
    ExploitKit,
    /// Keylogger: Monitors keystrokes and records them or sends them back to a central point.
    Keylogger,
    /// Ransomware: Encrypts files on a system, demanding ransom for access codes.
    Ransomware,
    /// RemoteAccessTrojan: A trojan capable of controlling a machine through remote commands.
    RemoteAccessTrojan,
    /// ResourceExploitation: Steals a system's resources, such as a malicious bitcoin miner.
    ResourceExploitation,
    /// RogueSecuritySoftware: A fake security product demanding money to clean phony infections.
    RogueSecuritySoftware,
    /// Rootkit: Hides its files or processes to conceal its presence and activities.
    Rootkit,
    /// ScreenCapture: Captures images from the target system's screen for exfiltration.
    ScreenCapture,
    /// Spyware: Gathers information on a user's system without their knowledge.
    Spyware,
    /// Trojan: Malicious program used to hack into a computer by misleading users.
    Trojan,
    /// Unknown: Not enough information to determine the type of malware.
    Unknown,
    /// Virus: Replicates by reproducing itself or infecting other programs.
    Virus,
    /// Webshell: Malicious script used to maintain persistent access on a compromised web application.
    Webshell,
    /// Wiper: Deletes files or entire disks on a machine.
    Wiper,
    /// Worm: Self-replicating program that executes itself without user intervention.
    Worm,
}

/// Represents the various types of opinions within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum OpinionType {
    StronglyAgree,
    Agree,
    #[default]
    Neutral,
    Disagree,
    StronglyDisagree,
}

// The members of the region ov open vocabulary
// Mimics python stix region
/// Represents the world regions based on the United Nations geoscheme within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum Region {
    Africa,
    EasternAfrica,
    MiddleAfrica,
    NorthernAfrica,
    SouthernAfrica,
    WesternAfrica,
    Americas,
    LatinAmericaCaribbean,
    SouthAmerica,
    Caribbean,
    CentralAmerica,
    NorthernAmerica,
    Asia,
    CentralAsia,
    EasternAsia,
    SouthernAsia,
    SouthEasternAsia,
    WesternAsia,
    Europe,
    EasternEurope,
    NorthernEurope,
    SouthernEurope,
    WesternEurope,
    Oceania,
    Antarctica,
    AustraliaNewZealand,
    Melanesia,
    Micronesia,
    Polynesia,
}

/// Represents the various types of reports within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum ReportType {
    AttackPattern,
    Campaign,
    Identity,
    Indicator,
    IntrusionSet,
    Malware,
    ObservedData,
    ThreatActor,
    ThreatReport,
    Tool,
    Vulnerability,
}

/// Represents the various roles of threat actors within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum ThreatActorRole {
    // Threat actor executes attacks either on behalf of themselves or at the direction of someone else.
    Agent,
    // The threat actor who directs the activities, goals, and objectives of the malicious activities.
    Director,
    // A threat actor acting by themselves.
    Independent,
    // Someone who designs the battle space.
    InfrastructureArchitect,
    // The threat actor who provides and supports the attack infrastructure.
    InfrastructureOperator,
    // The threat actor who authors malware or other malicious tools.
    MalwareAuthor,
    // The threat actor who funds the malicious activities.
    Sponsor,
}

/// Represents the various levels of threat actor sophistication within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum ThreatActorSophistication {
    // Can develop their own tools or scripts from known vulnerabilities.
    Advanced,
    // Can focus on the discovery and use of unknown malicious code.
    Expert,
    // Highly technical and proficient, capable of discovering new vulnerabilities.
    Innovator,
    // Can proficiently use existing attack frameworks and toolkits.
    Intermediate,
    // Can carry out random acts of disruption using tools they do not understand.
    None,
    // Can minimally use existing techniques and programs to exploit weaknesses.
    Minimal,
    // State actors creating vulnerabilities through influence in supply chains.
    Strategic,
}

/// Represents the various types of threat actors within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum ThreatActorType {
    // Highly motivated supporter of a social or political cause, potentially disruptive.
    Activist,
    // An organization competing in the same economic marketplace, seeking advantage.
    Competitor,
    // An enterprise organized for large-scale criminal activity for profit.
    CrimeSyndicate,
    // Individual committing computer crimes for personal financial gain.
    Criminal,
    // An individual breaking into networks for thrill or challenge.
    Hacker,
    // A non-hostile insider unintentionally exposing the organization to harm.
    InsiderAccidental,
    // Current or former insiders seeking revenge for perceived wrongs.
    InsiderDisgruntled,
    // Entities working for or directed by a nation state, with significant resources.
    NationState,
    // Seeks to cause embarrassment and brand damage by exposing sensitive information.
    Sensationalist,
    // Secretly collects sensitive information for use, dissemination, or sale.
    Spy,
    // Uses extreme violence to advance a social or political agenda.
    Terrorist,
    // Insufficient information to determine the type of threat actor.
    Unknown,
}

/// Represents the various ToolType of threat actors within the STIX framework.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter, Default)]
#[strum(serialize_all = "kebab-case")]
pub enum ToolType {
    CredentialExploitation,
    DenialOfService,
    Exploitation,
    InformationGathering,
    NetworkCapture,
    RemoteAccess,
    VulnerabilityScanning,
    #[default]
    Unknown,
}
