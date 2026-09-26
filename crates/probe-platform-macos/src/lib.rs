//! Read-only macOS network observation adapter.
//!
//! The adapter executes only Apple's public `/sbin/ifconfig` and `/sbin/route`
//! command-line interfaces. It never invokes a shell, requests elevation, reads
//! product configuration, or mutates network state.

use std::{
    collections::BTreeSet,
    io,
    net::IpAddr,
    process::{Command, Output},
};

use serde::{Deserialize, Serialize};

const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_INTERFACES: usize = 256;
const MAX_ADDRESSES_PER_INTERFACE: usize = 64;

#[derive(Debug, Clone, Serialize)]
pub struct PlatformSupport {
    pub os: &'static str,
    pub minimum_version: &'static str,
    pub architecture: &'static str,
    pub network_mutation: bool,
    pub inspection_implemented: bool,
}

#[must_use]
pub const fn support() -> PlatformSupport {
    PlatformSupport {
        os: "macos",
        minimum_version: "13",
        architecture: "arm64",
        network_mutation: false,
        inspection_implemented: true,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    Observed,
    Inferred,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyClass {
    Public,
    PrivateLocal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceCategory {
    Loopback,
    Link,
    TunnelLike,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceAddress {
    /// Private-local evidence. Public exports must remove this field.
    pub address: IpAddr,
    pub family: AddressFamily,
    pub privacy: PrivacyClass,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceObservation {
    /// OS interface identifier. Private-local only.
    pub name: String,
    pub name_privacy: PrivacyClass,
    pub category: InterfaceCategory,
    /// Category is inferred from bounded OS facts; it never identifies a vendor.
    pub category_provenance: Provenance,
    pub is_up: bool,
    pub is_loopback: bool,
    pub status_provenance: Provenance,
    pub addresses: Vec<InterfaceAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicInterfaceSummary {
    pub category: InterfaceCategory,
    pub is_up: bool,
    pub is_loopback: bool,
    pub address_families: Vec<AddressFamily>,
}

impl InterfaceObservation {
    #[must_use]
    pub fn public_summary(&self) -> PublicInterfaceSummary {
        let families: BTreeSet<_> = self.addresses.iter().map(|item| item.family).collect();
        PublicInterfaceSummary {
            category: self.category,
            is_up: self.is_up,
            is_loopback: self.is_loopback,
            address_families: families.into_iter().collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyAvailability {
    pub ipv4: bool,
    pub ipv6: bool,
    pub provenance: Provenance,
    pub limitation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteObservation {
    pub requested_family: Option<AddressFamily>,
    /// Gateway and interface are private-local topology evidence.
    pub gateway: Option<String>,
    pub gateway_privacy: PrivacyClass,
    pub interface_name: Option<String>,
    pub interface_privacy: PrivacyClass,
    pub interface_category: Option<InterfaceCategory>,
    pub provenance: Provenance,
    pub limitation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicRouteSummary {
    pub requested_family: Option<AddressFamily>,
    pub gateway_present: bool,
    pub interface_category: Option<InterfaceCategory>,
    pub provenance: Provenance,
}

impl RouteObservation {
    #[must_use]
    pub fn public_summary(&self) -> PublicRouteSummary {
        PublicRouteSummary {
            requested_family: self.requested_family,
            gateway_present: self.gateway.is_some(),
            interface_category: self.interface_category,
            provenance: self.provenance,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelObservation {
    pub tunnel_like_count: usize,
    /// Interface names remain local-only.
    pub interface_names: Vec<String>,
    pub names_privacy: PrivacyClass,
    pub default_route_uses_tunnel_like: Option<bool>,
    pub provenance: Provenance,
    pub limitation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicTunnelSummary {
    pub tunnel_like_count: usize,
    pub default_route_uses_tunnel_like: Option<bool>,
    pub provenance: Provenance,
    pub limitation: String,
}

impl TunnelObservation {
    #[must_use]
    pub fn public_summary(&self) -> PublicTunnelSummary {
        PublicTunnelSummary {
            tunnel_like_count: self.tunnel_like_count,
            default_route_uses_tunnel_like: self.default_route_uses_tunnel_like,
            provenance: self.provenance,
            limitation: self.limitation.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformSnapshot {
    pub adapter_version: String,
    pub interfaces: Vec<InterfaceObservation>,
    pub availability: FamilyAvailability,
    pub default_route: Option<RouteObservation>,
    pub targeted_routes: Vec<RouteObservation>,
    pub tunnel: TunnelObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformErrorCode {
    PermissionDenied,
    Unsupported,
    CommandFailed,
    MalformedOutput,
    ResourceLimit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformError {
    pub code: PlatformErrorCode,
    pub safe_summary: String,
}

impl std::fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.safe_summary)
    }
}

impl std::error::Error for PlatformError {}

pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<Output>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<Output> {
        Command::new(program).args(args).output()
    }
}

#[derive(Debug, Clone)]
pub struct MacOsAdapter<R = SystemCommandRunner> {
    runner: R,
}

impl Default for MacOsAdapter<SystemCommandRunner> {
    fn default() -> Self {
        Self {
            runner: SystemCommandRunner,
        }
    }
}

impl<R: CommandRunner> MacOsAdapter<R> {
    #[must_use]
    pub const fn new(runner: R) -> Self {
        Self { runner }
    }

    pub fn observe_interfaces(&self) -> Result<Vec<InterfaceObservation>, PlatformError> {
        ensure_supported_platform()?;
        let output = self.execute("/sbin/ifconfig", &["-a"])?;
        parse_ifconfig(&output)
    }

    pub fn observe_route(
        &self,
        destination: Option<IpAddr>,
        interfaces: &[InterfaceObservation],
    ) -> Result<RouteObservation, PlatformError> {
        ensure_supported_platform()?;
        let destination_text = destination
            .map(|address| address.to_string())
            .unwrap_or_else(|| "default".to_owned());
        let output = self.execute("/sbin/route", &["-n", "get", &destination_text])?;
        parse_route(&output, destination, interfaces)
    }

    pub fn snapshot(&self) -> Result<PlatformSnapshot, PlatformError> {
        self.snapshot_with_targets(&[])
    }

    pub fn snapshot_with_targets(
        &self,
        targets: &[IpAddr],
    ) -> Result<PlatformSnapshot, PlatformError> {
        let interfaces = self.observe_interfaces()?;
        let availability = availability(&interfaces);
        let default_route = self.observe_route(None, &interfaces).ok();
        let targeted_routes = targets
            .iter()
            .filter_map(|target| self.observe_route(Some(*target), &interfaces).ok())
            .collect();
        let tunnel = tunnel_observation(&interfaces, default_route.as_ref());
        Ok(PlatformSnapshot {
            adapter_version: "0.1.0".to_owned(),
            interfaces,
            availability,
            default_route,
            targeted_routes,
            tunnel,
        })
    }

    fn execute(&self, program: &str, args: &[&str]) -> Result<String, PlatformError> {
        let output = self.runner.run(program, args).map_err(map_io_error)?;
        if output.stdout.len() > MAX_COMMAND_OUTPUT_BYTES
            || output.stderr.len() > MAX_COMMAND_OUTPUT_BYTES
        {
            return Err(error(
                PlatformErrorCode::ResourceLimit,
                "platform command output exceeded the fixed safety bound",
            ));
        }
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
            let code = if stderr.contains("not permitted") || stderr.contains("permission denied") {
                PlatformErrorCode::PermissionDenied
            } else {
                PlatformErrorCode::CommandFailed
            };
            return Err(error(code, "read-only platform observation failed"));
        }
        String::from_utf8(output.stdout).map_err(|_| {
            error(
                PlatformErrorCode::MalformedOutput,
                "platform command returned non-UTF-8 output",
            )
        })
    }
}

fn ensure_supported_platform() -> Result<(), PlatformError> {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Ok(())
    } else {
        Err(error(
            PlatformErrorCode::Unsupported,
            "Open Probe V0.1 supports macOS arm64 only",
        ))
    }
}

fn map_io_error(source: io::Error) -> PlatformError {
    let code = match source.kind() {
        io::ErrorKind::PermissionDenied => PlatformErrorCode::PermissionDenied,
        io::ErrorKind::NotFound | io::ErrorKind::Unsupported => PlatformErrorCode::Unsupported,
        _ => PlatformErrorCode::CommandFailed,
    };
    error(code, "read-only platform command could not be executed")
}

fn error(code: PlatformErrorCode, summary: &str) -> PlatformError {
    PlatformError {
        code,
        safe_summary: summary.to_owned(),
    }
}

pub fn parse_ifconfig(input: &str) -> Result<Vec<InterfaceObservation>, PlatformError> {
    if input.len() > MAX_COMMAND_OUTPUT_BYTES {
        return Err(error(
            PlatformErrorCode::ResourceLimit,
            "interface snapshot exceeded the fixed safety bound",
        ));
    }
    let mut observations = Vec::new();
    let mut current: Option<InterfaceObservation> = None;

    for line in input.lines() {
        if !line.starts_with(char::is_whitespace) && line.contains(": flags=") {
            if let Some(item) = current.take() {
                observations.push(item);
            }
            if observations.len() >= MAX_INTERFACES {
                return Err(error(
                    PlatformErrorCode::ResourceLimit,
                    "interface count exceeded the fixed safety bound",
                ));
            }
            let Some((name, remainder)) = line.split_once(": flags=") else {
                continue;
            };
            let flags = remainder
                .split_once('<')
                .and_then(|(_, value)| value.split_once('>'))
                .map_or("", |(value, _)| value);
            let is_loopback = flags.split(',').any(|flag| flag == "LOOPBACK");
            let is_up = flags.split(',').any(|flag| flag == "UP");
            current = Some(InterfaceObservation {
                name: name.to_owned(),
                name_privacy: PrivacyClass::PrivateLocal,
                category: classify_interface(name, is_loopback),
                category_provenance: Provenance::Inferred,
                is_up,
                is_loopback,
                status_provenance: Provenance::Observed,
                addresses: Vec::new(),
            });
            continue;
        }

        let Some(item) = current.as_mut() else {
            continue;
        };
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("inet ") {
            push_address(item, value.split_whitespace().next(), AddressFamily::Ipv4)?;
        } else if let Some(value) = trimmed.strip_prefix("inet6 ") {
            let raw = value.split_whitespace().next().map(|address| {
                address
                    .split_once('%')
                    .map_or(address, |(without_scope, _)| without_scope)
            });
            push_address(item, raw, AddressFamily::Ipv6)?;
        } else if let Some(status) = trimmed.strip_prefix("status: ") {
            item.is_up = status.eq_ignore_ascii_case("active") || item.is_up;
        }
    }
    if let Some(item) = current {
        observations.push(item);
    }
    if observations.is_empty() {
        return Err(error(
            PlatformErrorCode::MalformedOutput,
            "interface snapshot contained no recognizable interfaces",
        ));
    }
    Ok(observations)
}

fn push_address(
    item: &mut InterfaceObservation,
    raw: Option<&str>,
    family: AddressFamily,
) -> Result<(), PlatformError> {
    if item.addresses.len() >= MAX_ADDRESSES_PER_INTERFACE {
        return Err(error(
            PlatformErrorCode::ResourceLimit,
            "address count exceeded the per-interface safety bound",
        ));
    }
    if let Some(address) = raw.and_then(|value| value.parse::<IpAddr>().ok()) {
        item.addresses.push(InterfaceAddress {
            address,
            family,
            privacy: PrivacyClass::PrivateLocal,
            provenance: Provenance::Observed,
        });
    }
    Ok(())
}

fn classify_interface(name: &str, is_loopback: bool) -> InterfaceCategory {
    if is_loopback {
        InterfaceCategory::Loopback
    } else if name.starts_with("utun")
        || name.starts_with("tun")
        || name.starts_with("tap")
        || name.starts_with("ipsec")
    {
        InterfaceCategory::TunnelLike
    } else if name.starts_with("en") || name.starts_with("bridge") || name.starts_with("awdl") {
        InterfaceCategory::Link
    } else {
        InterfaceCategory::Other
    }
}

#[must_use]
pub fn availability(interfaces: &[InterfaceObservation]) -> FamilyAvailability {
    let usable = interfaces
        .iter()
        .filter(|item| item.is_up && !item.is_loopback);
    let mut ipv4 = false;
    let mut ipv6 = false;
    for interface in usable {
        for address in &interface.addresses {
            match address.family {
                AddressFamily::Ipv4 if !address.address.is_loopback() => ipv4 = true,
                AddressFamily::Ipv6 if !address.address.is_loopback() => ipv6 = true,
                _ => {}
            }
        }
    }
    FamilyAvailability {
        ipv4,
        ipv6,
        provenance: Provenance::Observed,
        limitation: "Address presence is observed independently per family; it does not prove Internet reachability or health.".to_owned(),
    }
}

pub fn parse_route(
    input: &str,
    destination: Option<IpAddr>,
    interfaces: &[InterfaceObservation],
) -> Result<RouteObservation, PlatformError> {
    if input.len() > MAX_COMMAND_OUTPUT_BYTES {
        return Err(error(
            PlatformErrorCode::ResourceLimit,
            "route result exceeded the fixed safety bound",
        ));
    }
    let mut gateway = None;
    let mut interface_name = None;
    for line in input.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("gateway:") {
            gateway = nonempty(value);
        } else if let Some(value) = trimmed.strip_prefix("interface:") {
            interface_name = nonempty(value);
        }
    }
    if gateway.is_none() && interface_name.is_none() {
        return Err(error(
            PlatformErrorCode::MalformedOutput,
            "route result contained no gateway or interface",
        ));
    }
    let category = interface_name.as_deref().and_then(|name| {
        interfaces
            .iter()
            .find(|item| item.name == name)
            .map(|item| item.category)
    });
    Ok(RouteObservation {
        requested_family: destination.map(|address| match address {
            IpAddr::V4(_) => AddressFamily::Ipv4,
            IpAddr::V6(_) => AddressFamily::Ipv6,
        }),
        gateway,
        gateway_privacy: PrivacyClass::PrivateLocal,
        interface_name,
        interface_privacy: PrivacyClass::PrivateLocal,
        interface_category: category,
        provenance: Provenance::Observed,
        limitation: "This is the OS-selected route at observation time; it does not prove the physical path or identify a VPN/proxy product.".to_owned(),
    })
}

fn nonempty(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

#[must_use]
pub fn tunnel_observation(
    interfaces: &[InterfaceObservation],
    default_route: Option<&RouteObservation>,
) -> TunnelObservation {
    let names: Vec<_> = interfaces
        .iter()
        .filter(|item| item.category == InterfaceCategory::TunnelLike)
        .map(|item| item.name.clone())
        .take(MAX_INTERFACES)
        .collect();
    let uses_tunnel = default_route.and_then(|route| {
        route
            .interface_name
            .as_deref()
            .map(|name| names.iter().any(|candidate| candidate == name))
    });
    TunnelObservation {
        tunnel_like_count: names.len(),
        interface_names: names,
        names_privacy: PrivacyClass::PrivateLocal,
        default_route_uses_tunnel_like: uses_tunnel,
        provenance: Provenance::Inferred,
        limitation: "A TUN-like interface name or selected route does not identify its owner, prove enforcement, or reveal a VPN/proxy product.".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IFCONFIG: &str = include_str!("../tests/fixtures/ifconfig.sanitized.txt");
    const ROUTE: &str = include_str!("../tests/fixtures/route-default.sanitized.txt");

    #[test]
    fn parses_interfaces_and_independent_address_families() {
        let interfaces = parse_ifconfig(IFCONFIG).expect("fixture parses");
        assert_eq!(interfaces.len(), 3);
        let availability = availability(&interfaces);
        assert!(availability.ipv4);
        assert!(availability.ipv6);
        let tunnel = interfaces
            .iter()
            .find(|item| item.category == InterfaceCategory::TunnelLike)
            .expect("tunnel present");
        assert_eq!(tunnel.category_provenance, Provenance::Inferred);
    }

    #[test]
    fn route_export_removes_topology_identifiers() {
        let interfaces = parse_ifconfig(IFCONFIG).expect("fixture parses");
        let route = parse_route(ROUTE, None, &interfaces).expect("route parses");
        assert_eq!(route.interface_name.as_deref(), Some("utun7"));
        assert_eq!(
            route.interface_category,
            Some(InterfaceCategory::TunnelLike)
        );
        let public = serde_json::to_value(route.public_summary()).expect("serializes");
        assert!(public.get("gateway").is_none());
        assert!(public.get("interface_name").is_none());
    }

    #[test]
    fn ipv6_absence_is_not_a_health_verdict() {
        let input = "en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tinet 192.0.2.2 netmask 0xffffff00\n\tstatus: active\n";
        let interfaces = parse_ifconfig(input).expect("fixture parses");
        let observed = availability(&interfaces);
        assert!(observed.ipv4);
        assert!(!observed.ipv6);
        assert_eq!(observed.provenance, Provenance::Observed);
    }

    #[test]
    fn malformed_and_oversized_inputs_fail_safely() {
        assert_eq!(
            parse_ifconfig("not ifconfig").expect_err("must fail").code,
            PlatformErrorCode::MalformedOutput
        );
        let oversized = "x".repeat(MAX_COMMAND_OUTPUT_BYTES + 1);
        assert_eq!(
            parse_route(&oversized, None, &[])
                .expect_err("must fail")
                .code,
            PlatformErrorCode::ResourceLimit
        );
    }

    #[test]
    fn tunnel_observation_is_bounded_and_does_not_name_a_product() {
        let interfaces = parse_ifconfig(IFCONFIG).expect("fixture parses");
        let route = parse_route(ROUTE, None, &interfaces).expect("route parses");
        let observed = tunnel_observation(&interfaces, Some(&route));
        assert_eq!(observed.tunnel_like_count, 1);
        assert_eq!(observed.default_route_uses_tunnel_like, Some(true));
        assert!(!observed.limitation.to_ascii_lowercase().contains("clash"));
    }
}
