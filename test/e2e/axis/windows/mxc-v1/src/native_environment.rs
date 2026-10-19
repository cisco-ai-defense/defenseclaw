// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Fixed contributor metadata only. No native call, environment lookup or path
// opening belongs here; the parent's held native identity supplies the folder.
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"DCENV1\r\n";
const MAX_UNITS: usize = 2048;

// The parent must keep the original private startup paths stable across native
// known-folder/SID queries. Child-request paths are a separate inner fixture.
pub(super) struct StartupEnvironment {
    values: BTreeMap<String, OsString>,
}

impl StartupEnvironment {
    fn entries(
        entries: impl IntoIterator<Item = (OsString, OsString)>,
        canary_required: bool,
    ) -> io::Result<BTreeMap<String, OsString>> {
        const NAMES: [&str; 8] = [
            "SYSTEMROOT",
            "WINDIR",
            "HOME",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "TEMP",
            "TMP",
        ];
        let mut values = BTreeMap::new();
        let mut count = 0;
        let mut canary_seen = false;
        for (name, value) in entries {
            count += 1;
            if count > 9 {
                return Err(refused());
            }
            let name = name
                .to_str()
                .filter(|name| name.len() <= 32)
                .ok_or_else(refused)?;
            let name = name.to_ascii_uppercase();
            if name == "DC_AXIS_INHERIT_CANARY" {
                if !canary_required || canary_seen || value != "fixed-public" {
                    return Err(refused());
                }
                canary_seen = true;
            } else if !NAMES.contains(&name.as_str()) || values.insert(name, value).is_some() {
                return Err(refused());
            }
        }
        if values.len() != NAMES.len() || canary_seen != canary_required {
            return Err(refused());
        }
        Ok(values)
    }

    pub(super) fn from_startup_entries(
        entries: impl IntoIterator<Item = (OsString, OsString)>,
        system: &Path,
        cwd: &Path,
    ) -> io::Result<Self> {
        let values = Self::entries(entries, false)?;
        for value in values.values() {
            disk_units(value)?;
        }
        if disk_units(&values["SYSTEMROOT"])? != disk_units(system.as_os_str())?
            || disk_units(&values["WINDIR"])? != disk_units(system.as_os_str())?
        {
            return Err(refused());
        }
        let home = PathBuf::from(OsString::from_wide(&disk_units(&values["HOME"])?));
        if home.file_name() != Some(OsStr::new("home")) {
            return Err(refused());
        }
        let root = home.parent().ok_or_else(refused)?;
        let suffix = root
            .file_name()
            .and_then(OsStr::to_str)
            .and_then(|name| name.strip_prefix("psec-headless-"))
            .filter(|suffix| !suffix.is_empty())
            .ok_or_else(refused)?;
        if !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(refused());
        }
        for (name, expected) in [
            ("USERPROFILE", home.clone()),
            ("APPDATA", home.join(r"AppData\Roaming")),
            ("LOCALAPPDATA", home.join(r"AppData\Local")),
            ("TEMP", root.join("tmp")),
            ("TMP", root.join("tmp")),
        ] {
            if disk_units(&values[name])? != disk_units(expected.as_os_str())? {
                return Err(refused());
            }
        }
        if disk_units(cwd.as_os_str())? != disk_units(root.join("workspace").as_os_str())? {
            return Err(refused());
        }
        Ok(Self { values })
    }

    pub(super) fn require_unchanged(
        &self,
        entries: impl IntoIterator<Item = (OsString, OsString)>,
        canary_required: bool,
    ) -> io::Result<()> {
        if Self::entries(entries, canary_required)? != self.values {
            return Err(io::Error::other(
                "original private startup environment changed",
            ));
        }
        Ok(())
    }

    pub(super) fn require_caller_local_app_data(&self, caller: &OsStr) -> io::Result<()> {
        if caller != self.local_app_data() {
            return Err(io::Error::other(
                "caller known-folder differs from private startup",
            ));
        }
        Ok(())
    }

    pub(super) fn local_app_data(&self) -> &OsStr {
        &self.values["LOCALAPPDATA"]
    }
}

// Refusal-only evidence. These relationships never authorize a path or alter
// the exact mapper below. No input string, hash, length or identity is retained.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ProfileRefusalClassification {
    category: &'static str,
    caller_verbatim_disk: bool,
    native_verbatim_disk: bool,
    exact_prefix: Option<bool>,
    ordinal_prefix: Option<bool>,
    native_suffix_shape: bool,
    native_base_exact_caller: Option<bool>,
    native_base_ordinal_caller: Option<bool>,
    native_base_exact_startup: Option<bool>,
    native_base_ordinal_startup: Option<bool>,
    caller_base_exact_startup: Option<bool>,
    caller_base_ordinal_startup: Option<bool>,
}

impl std::fmt::Display for ProfileRefusalClassification {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "native profile refusal classification: category={} caller_verbatim_disk={} native_verbatim_disk={} exact_prefix={:?} ordinal_prefix={:?} native_suffix_shape={} native_base_exact_caller={:?} native_base_ordinal_caller={:?} native_base_exact_startup={:?} native_base_ordinal_startup={:?} caller_base_exact_startup={:?} caller_base_ordinal_startup={:?}",
            self.category,
            self.caller_verbatim_disk,
            self.native_verbatim_disk,
            self.exact_prefix,
            self.ordinal_prefix,
            self.native_suffix_shape,
            self.native_base_exact_caller,
            self.native_base_ordinal_caller,
            self.native_base_exact_startup,
            self.native_base_ordinal_startup,
            self.caller_base_exact_startup,
            self.caller_base_ordinal_startup,
        )
    }
}

pub(super) fn classify_profile_refusal(
    caller: &OsStr,
    native: &OsStr,
    startup: &OsStr,
    ordinal_equal: impl Fn(&[u16], &[u16]) -> Option<bool>,
) -> ProfileRefusalClassification {
    let verbatim = |value: &OsStr| {
        let head: Vec<_> = value.encode_wide().take(7).collect();
        head.len() == 7
            && head[..4] == [92, 92, 63, 92]
            && ((65..=90).contains(&head[4]) || (97..=122).contains(&head[4]))
            && head[5..] == [58, 92]
    };
    let mut result = ProfileRefusalClassification {
        category: "invalid_path_shape",
        caller_verbatim_disk: verbatim(caller),
        native_verbatim_disk: verbatim(native),
        exact_prefix: None,
        ordinal_prefix: None,
        native_suffix_shape: false,
        native_base_exact_caller: None,
        native_base_ordinal_caller: None,
        native_base_exact_startup: None,
        native_base_ordinal_startup: None,
        caller_base_exact_startup: None,
        caller_base_ordinal_startup: None,
    };
    let (Ok(caller), Ok(native), Ok(startup)) =
        (disk_units(caller), disk_units(native), disk_units(startup))
    else {
        return result;
    };
    result.caller_base_exact_startup = Some(caller == startup);
    result.caller_base_ordinal_startup = ordinal_equal(&caller, &startup);
    let mut prefix = caller.clone();
    prefix.extend(r"\Packages\".encode_utf16());
    result.exact_prefix = Some(native.starts_with(&prefix));
    result.ordinal_prefix = native
        .get(..prefix.len())
        .map_or(Some(false), |head| ordinal_equal(head, &prefix));

    // Derive a base only from the exact component-boundary suffix accepted by
    // the existing grammar. A malformed suffix remains unclassified, even if
    // its leading bytes happen to match the expected caller prefix.
    let parts: Vec<_> = native.rsplitn(4, |unit| *unit == 92).collect();
    result.category = "unrecognized_suffix";
    if parts.len() != 4 || parts[2] != [80, 97, 99, 107, 97, 103, 101, 115] {
        return result;
    }
    let mut tail = parts[1].to_vec();
    tail.push(92);
    tail.extend_from_slice(parts[0]);
    if profile_component(&tail).is_err() || parts[3].len() < 3 {
        return result;
    }
    result.native_suffix_shape = true;
    let base = parts[3];
    result.native_base_exact_caller = Some(base == caller.as_slice());
    result.native_base_ordinal_caller = ordinal_equal(base, &caller);
    result.native_base_exact_startup = Some(base == startup.as_slice());
    result.native_base_ordinal_startup = ordinal_equal(base, &startup);
    result.category = if result.exact_prefix == Some(true) {
        "exact_prefix"
    } else if result.ordinal_prefix == Some(true) {
        "case_only_prefix"
    } else if result.ordinal_prefix == Some(false)
        && result.native_base_ordinal_caller == Some(false)
    {
        "different_base_string"
    } else {
        "ordinal_comparison_unknown"
    };
    result
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ExpectedEnvironment {
    pub(super) local_app_data: PathBuf,
    pub(super) temporary: PathBuf,
    pub(super) temporary_alias: PathBuf,
}

fn refused() -> io::Error {
    io::Error::other("native private environment binding refused")
}

fn disk_units(value: &OsStr) -> io::Result<Vec<u16>> {
    let raw: Vec<_> = value.encode_wide().take(MAX_UNITS + 1).collect();
    if raw.len() > MAX_UNITS || raw.contains(&0) {
        return Err(refused());
    }
    let value = raw.strip_prefix(&[92, 92, 63, 92]).unwrap_or(&raw);
    if value.len() < 4
        || !((65..=90).contains(&value[0]) || (97..=122).contains(&value[0]))
        || value[1..3] != [58, 92]
    {
        return Err(refused());
    }
    for component in value[3..].split(|unit| *unit == 92) {
        if component.is_empty()
            || component == [46]
            || component == [46, 46]
            || component.last().is_some_and(|unit| [32, 46].contains(unit))
            || component
                .iter()
                .any(|unit| *unit < 32 || [47, 58].contains(unit))
        {
            return Err(refused());
        }
    }
    Ok(value.to_vec())
}

fn ordinary_profile_component(component: &[u16]) -> bool {
    // Preserve one literal ordinary Windows component. No Unicode folding,
    // expansion, lossy conversion or path canonicalization supplies authority.
    if component.is_empty()
        || component.len() > 128
        || component == [46]
        || component == [46, 46]
        || component.last().is_some_and(|unit| [32, 46].contains(unit))
        || component
            .iter()
            .any(|unit| [92, 47, 58, 60, 62, 34, 124, 63, 42].contains(unit))
        || !std::char::decode_utf16(component.iter().copied())
            .all(|value| value.is_ok_and(|character| !character.is_control()))
    {
        return false;
    }
    // Device aliases remain special with an extension and with spaces before
    // that extension. Conservatively include COM/LPT0 as the HostStage floor.
    let mut stem = component.split(|unit| *unit == 46).next().unwrap();
    while stem.last() == Some(&32) {
        stem = &stem[..stem.len() - 1];
    }
    let stem: Vec<u16> = stem
        .iter()
        .map(|unit| {
            if (65..=90).contains(unit) {
                *unit + 32
            } else {
                *unit
            }
        })
        .collect();
    if ["con", "prn", "aux", "nul", "clock$", "conin$", "conout$"]
        .iter()
        .any(|name| stem.iter().copied().eq(name.encode_utf16()))
    {
        return false;
    }
    !(stem.len() == 4
        && (stem[..3] == [99, 111, 109] || stem[..3] == [108, 112, 116])
        && ((48..=57).contains(&stem[3]) || [0xb9, 0xb2, 0xb3].contains(&stem[3])))
}

fn profile_component(remainder: &[u16]) -> io::Result<&[u16]> {
    let parts: Vec<_> = remainder.split(|unit| *unit == 92).collect();
    if parts.len() != 2 || parts[1] != [65, 67] || !ordinary_profile_component(parts[0]) {
        return Err(io::Error::other("native profile component shape refused"));
    }
    Ok(parts[0])
}

impl ExpectedEnvironment {
    // The caller validates the same retained child token's User SID against
    // its own, then obtains this token's OS user profile root independently of
    // environment values. Admit only the explicit default LocalAppData floor;
    // redirected/other bases refuse. Carry one safe component, never a host
    // path, into the held private fixture. No host profile path is opened.
    pub(super) fn from_process_profile(
        root: &Path,
        process_user_profile: &OsStr,
        native_folder: &OsStr,
    ) -> io::Result<Self> {
        let mut prefix = disk_units(process_user_profile)?;
        prefix.extend(r"\AppData\Local\Packages\".encode_utf16());
        let native = disk_units(native_folder)?;
        let remainder = native
            .strip_prefix(prefix.as_slice())
            .ok_or_else(|| io::Error::other("native process user-profile base differs"))?;
        let profile = profile_component(remainder)?;
        let mapped = root
            .join(r"home\AppData\Local\Packages")
            .join(OsString::from_wide(profile))
            .join("AC");
        Self::from_native_folder(root, mapped.as_os_str())
    }

    pub(super) fn from_native_folder(root: &Path, folder: &OsStr) -> io::Result<Self> {
        let mut prefix = disk_units(root.as_os_str())?;
        prefix.extend(r"\home\AppData\Local\Packages\".encode_utf16());
        let value = disk_units(folder)?;
        let remainder = value.strip_prefix(prefix.as_slice()).ok_or_else(refused)?;
        profile_component(remainder)?;
        let local_app_data = PathBuf::from(folder);
        let temporary = local_app_data.join("Temp");
        disk_units(temporary.as_os_str())?;
        Ok(Self {
            local_app_data,
            temporary_alias: temporary.clone(),
            temporary,
        })
    }

    pub(super) fn write_to(&self, mut writer: impl Write) -> io::Result<()> {
        writer.write_all(MAGIC)?;
        for path in [&self.local_app_data, &self.temporary, &self.temporary_alias] {
            let units: Vec<_> = path.as_os_str().encode_wide().take(MAX_UNITS + 1).collect();
            if units.is_empty() || units.len() > MAX_UNITS || units.contains(&0) {
                return Err(refused());
            }
            writer.write_all(&(units.len() as u32).to_le_bytes())?;
            for unit in units {
                writer.write_all(&unit.to_le_bytes())?;
            }
        }
        writer.flush()
    }

    pub(super) fn read_from(mut reader: impl Read, root: &Path) -> io::Result<Self> {
        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(refused());
        }
        let mut paths = Vec::with_capacity(3);
        for _ in 0..3 {
            let mut count = [0; 4];
            reader.read_exact(&mut count)?;
            let count = u32::from_le_bytes(count) as usize;
            if count == 0 || count > MAX_UNITS {
                return Err(refused());
            }
            let mut units = Vec::with_capacity(count);
            for _ in 0..count {
                let mut unit = [0; 2];
                reader.read_exact(&mut unit)?;
                units.push(u16::from_le_bytes(unit));
            }
            if units.contains(&0) {
                return Err(refused());
            }
            paths.push(PathBuf::from(OsString::from_wide(&units)));
        }
        let expected = Self::from_native_folder(root, paths[0].as_os_str())?;
        if paths[1].as_os_str() != expected.temporary.as_os_str()
            || paths[2].as_os_str() != expected.temporary_alias.as_os_str()
        {
            return Err(refused());
        }
        let mut trailing = [0];
        if reader.read(&mut trailing)? != 0 {
            return Err(refused());
        }
        Ok(expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_profile_refusal_classifier_reports_bounded_relationships() {
        // Pure callback model: ASCII ordinal examples are deterministic here;
        // non-ASCII/native API failure remains unknown rather than guessed.
        let ordinal = |first: &[u16], second: &[u16]| {
            if !first.iter().chain(second).all(|unit| *unit <= 127) {
                return None;
            }
            Some(
                first
                    .iter()
                    .map(|unit| (*unit as u8).to_ascii_uppercase())
                    .eq(second.iter().map(|unit| (*unit as u8).to_ascii_uppercase())),
            )
        };
        let caller = OsStr::new(r"C:\fixed-caller\AppData\Local");
        let startup = OsStr::new(r"C:\fixed-private\psec-headless-01\home\AppData\Local");
        let exact = OsStr::new(r"C:\fixed-caller\AppData\Local\Packages\native-profile_1\AC");
        let same = classify_profile_refusal(caller, exact, startup, ordinal);
        assert_eq!(same.category, "exact_prefix");
        assert_eq!(same.exact_prefix, Some(true));
        assert_eq!(same.ordinal_prefix, Some(true));
        assert_eq!(same.native_base_exact_caller, Some(true));
        assert_eq!(same.native_base_ordinal_startup, Some(false));
        assert_eq!(same.caller_base_exact_startup, Some(false));
        let prefixed = classify_profile_refusal(
            caller,
            OsStr::new(r"\\?\C:\fixed-caller\AppData\Local\Packages\native-profile_1\AC"),
            startup,
            ordinal,
        );
        assert_eq!(prefixed.category, "exact_prefix");
        assert!(!prefixed.caller_verbatim_disk && prefixed.native_verbatim_disk);
        let case = classify_profile_refusal(
            caller,
            OsStr::new(r"c:\FIXED-CALLER\appdata\local\Packages\native-profile_1\AC"),
            startup,
            ordinal,
        );
        assert_eq!(case.category, "case_only_prefix");
        assert_eq!(case.exact_prefix, Some(false));
        assert_eq!(case.ordinal_prefix, Some(true));
        assert_eq!(case.native_base_exact_caller, Some(false));
        assert_eq!(case.native_base_ordinal_caller, Some(true));
        let different = classify_profile_refusal(
            caller,
            OsStr::new(r"D:\other-caller\AppData\Local\Packages\native-profile_1\AC"),
            startup,
            ordinal,
        );
        assert_eq!(different.category, "different_base_string");
        assert_eq!(different.native_base_ordinal_caller, Some(false));
        let startup_folder = Path::new(startup).join(r"Packages\native-profile_1\AC");
        let private =
            classify_profile_refusal(caller, startup_folder.as_os_str(), startup, ordinal);
        assert_eq!(private.category, "different_base_string");
        assert_eq!(private.native_base_exact_startup, Some(true));
        let private_caller = classify_profile_refusal(startup, exact, startup, ordinal);
        assert_eq!(private_caller.caller_base_exact_startup, Some(true));
        assert_eq!(private_caller.native_base_exact_caller, Some(false));
        for malformed in [
            r"C:\fixed-caller\AppData\Local\Packages\native-profile_1\extra\AC",
            r"C:\fixed-caller\AppData\Local\Packages\..\AC",
            r"C:\fixed-caller\AppData\Local\Packages\native-profile_1\LocalCache",
        ] {
            let result = classify_profile_refusal(caller, OsStr::new(malformed), startup, ordinal);
            assert!(!result.native_suffix_shape);
            assert_eq!(result.native_base_exact_caller, None);
            assert!(matches!(
                result.category,
                "unrecognized_suffix" | "invalid_path_shape"
            ));
        }
        let unknown = classify_profile_refusal(caller, exact, startup, |_, _| None);
        assert_eq!(unknown.category, "exact_prefix"); // exact bytes remain known
        assert_eq!(unknown.ordinal_prefix, None);
        let unknown = classify_profile_refusal(
            caller,
            OsStr::new(r"C:\fixed-λ\AppData\Local\Packages\native-profile_1\AC"),
            startup,
            ordinal,
        );
        assert_eq!(unknown.category, "ordinal_comparison_unknown");
        let text = different.to_string();
        assert!(text.len() < 1024);
        assert!(!text.contains("fixed-caller") && !text.contains("other-caller"));
        assert!(!text.contains("C:") && !text.contains("D:") && !text.contains("native-profile"));
        // Diagnostic classification never changes exact admission.
        let root = Path::new(r"C:\fixed-private\dc-axis-windows-psec-fixed");
        assert!(
            ExpectedEnvironment::from_process_profile(root, OsStr::new(r"C:\fixed-caller"), exact)
                .is_ok()
        );
        assert!(
            ExpectedEnvironment::from_process_profile(
                root,
                OsStr::new(r"C:\fixed-caller"),
                OsStr::new(r"c:\FIXED-CALLER\appdata\local\Packages\native-profile_1\AC")
            )
            .is_err()
        );
    }

    fn fixed_startup() -> (Vec<(OsString, OsString)>, PathBuf, PathBuf) {
        let root = Path::new(r"C:\fixed-private\psec-headless-01");
        let home = root.join("home");
        let system = PathBuf::from(r"C:\Windows");
        let values = [
            ("SYSTEMROOT", system.clone()),
            ("WINDIR", system.clone()),
            ("HOME", home.clone()),
            ("USERPROFILE", home.clone()),
            ("APPDATA", home.join(r"AppData\Roaming")),
            ("LOCALAPPDATA", home.join(r"AppData\Local")),
            ("TEMP", root.join("tmp")),
            ("TMP", root.join("tmp")),
        ]
        .into_iter()
        .map(|(name, path)| (OsString::from(name), path.into_os_string()))
        .collect();
        (values, system, root.join("workspace"))
    }

    #[test]
    fn startup_environment_requires_exact_eight_private_values() {
        let (entries, system, cwd) = fixed_startup();
        assert!(StartupEnvironment::from_startup_entries(entries.clone(), &system, &cwd).is_ok());
        let mut prefixed = entries.clone();
        prefixed[2].1 = OsString::from(r"\\?\C:\fixed-private\psec-headless-01\home");
        assert!(StartupEnvironment::from_startup_entries(prefixed, &system, &cwd).is_ok());
        let mut invalid = Vec::new();
        let mut missing = entries.clone();
        missing.pop();
        invalid.push(missing);
        let mut unexpected = entries.clone();
        unexpected.push(("PATH".into(), r"C:\unrelated".into()));
        invalid.push(unexpected);
        let mut duplicate = entries.clone();
        duplicate.push(("home".into(), entries[2].1.clone()));
        invalid.push(duplicate);
        let mut bad_name = entries.clone();
        bad_name[0].0 = OsString::from_wide(&[0xd800]);
        invalid.push(bad_name);
        for (index, value) in [
            (0, r"D:\other-system"),
            (1, r"D:\other-system"),
            (2, r"C:\fixed-private\psec-headless-01\home\..\home"),
            (3, r"C:\unrelated\home"),
            (4, r"C:\fixed-private\psec-headless-01\home\AppData\Local"),
            (5, r"C:\fixed-private\psec-headless-01\home\AppData\Roaming"),
            (6, r"C:\unrelated\tmp"),
            (7, r"C:\unrelated\tmp"),
            (7, ""),
            (7, "C:\\fixed\0hidden"),
        ] {
            let mut changed = entries.clone();
            changed[index].1 = value.into();
            invalid.push(changed);
        }
        for changed in invalid {
            assert!(StartupEnvironment::from_startup_entries(changed, &system, &cwd).is_err());
        }
        for basename in ["unrelated-stage", "psec-headless-", "psec-headless-unsafe."] {
            let renamed: Vec<_> = entries
                .iter()
                .map(|(name, value)| {
                    (
                        name.clone(),
                        OsString::from(
                            value
                                .to_str()
                                .unwrap()
                                .replace("psec-headless-01", basename),
                        ),
                    )
                })
                .collect();
            let renamed_cwd =
                PathBuf::from(cwd.to_str().unwrap().replace("psec-headless-01", basename));
            assert!(
                StartupEnvironment::from_startup_entries(renamed, &system, &renamed_cwd).is_err()
            );
        }
        let mut oversized = entries.clone();
        oversized[7].1 = OsString::from(format!(r"C:\{}", "x".repeat(MAX_UNITS)));
        assert!(StartupEnvironment::from_startup_entries(oversized, &system, &cwd).is_err());
        assert!(
            StartupEnvironment::from_startup_entries(
                entries,
                &system,
                Path::new(r"C:\unrelated\workspace")
            )
            .is_err()
        );
    }

    #[test]
    fn startup_environment_snapshot_refuses_drift_and_canary_misuse() {
        let (entries, system, cwd) = fixed_startup();
        let snapshot =
            StartupEnvironment::from_startup_entries(entries.clone(), &system, &cwd).unwrap();
        assert!(snapshot.require_unchanged(entries.clone(), false).is_ok());
        assert!(
            snapshot
                .require_caller_local_app_data(snapshot.local_app_data())
                .is_ok()
        );
        assert!(
            snapshot
                .require_caller_local_app_data(OsStr::new(r"C:\Users\fixed-OS-user\AppData\Local"))
                .is_err()
        );
        assert!(
            snapshot
                .require_caller_local_app_data(OsStr::new(
                    r"c:\FIXED-PRIVATE\psec-headless-01\home\AppData\Local"
                ))
                .is_err()
        );
        assert!(snapshot.require_unchanged(entries.clone(), true).is_err());
        let mut with_canary = entries.clone();
        with_canary.push(("DC_AXIS_INHERIT_CANARY".into(), "fixed-public".into()));
        assert!(
            snapshot
                .require_unchanged(with_canary.clone(), true)
                .is_ok()
        );
        assert!(
            snapshot
                .require_unchanged(with_canary.clone(), false)
                .is_err()
        );
        assert!(
            StartupEnvironment::from_startup_entries(with_canary.clone(), &system, &cwd).is_err()
        );
        for index in 0..entries.len() {
            let mut changed = with_canary.clone();
            changed[index].1.push("-changed");
            assert!(snapshot.require_unchanged(changed, true).is_err());
        }
        let mut wrong = with_canary.clone();
        wrong.last_mut().unwrap().1 = "different".into();
        assert!(snapshot.require_unchanged(wrong, true).is_err());
        let mut duplicate = with_canary.clone();
        duplicate.push(("dc_axis_inherit_canary".into(), "fixed-public".into()));
        assert!(snapshot.require_unchanged(duplicate, true).is_err());
        let mut unexpected = with_canary;
        unexpected.push(("FIXED_UNEXPECTED_MARKER".into(), "fixed-public".into()));
        assert!(snapshot.require_unchanged(unexpected, true).is_err());
    }

    #[test]
    fn native_folder_requires_exact_private_branch_and_one_profile_component() {
        let root = Path::new(r"C:\fixed-private\dc-axis-windows-psec-fixed");
        for folder in [
            r"C:\fixed-private\dc-axis-windows-psec-fixed\home\AppData\Local\Packages\native-profile_1\AC",
            r"\\?\C:\fixed-private\dc-axis-windows-psec-fixed\home\AppData\Local\Packages\native-profile_1\AC",
        ] {
            assert!(ExpectedEnvironment::from_native_folder(root, OsStr::new(folder)).is_ok());
        }
        for folder in [
            r"C:\Users\real-user\AppData\Local\Packages\profile\AC",
            r"D:\fixed-private\dc-axis-windows-psec-fixed\home\AppData\Local\Packages\profile\AC",
            r"C:\fixed-private\dc-axis-windows-psec-fixed-other\home\AppData\Local\Packages\profile\AC",
            r"C:\fixed-private\dc-axis-windows-psec-fixed\home\AppData\Local\Packages\profile\extra\AC",
            r"C:\fixed-private\dc-axis-windows-psec-fixed\home\AppData\Local\Packages\..\AC",
            r"C:\fixed-private\dc-axis-windows-psec-fixed\home\AppData\Local\Packages\profile.\AC",
            r"C:\fixed-private\dc-axis-windows-psec-fixed\home\AppData\Local\Packages\profile:ads\AC",
            r"C:\fixed-private\dc-axis-windows-psec-fixed\home\AppData\Local\Packages\profile\LocalCache",
            r"\\server\share\home\AppData\Local\Packages\profile\AC",
        ] {
            assert!(ExpectedEnvironment::from_native_folder(root, OsStr::new(folder)).is_err());
        }
        // OS root and native folder must agree exactly before a component
        // transfers. Environment/caller-known-folder values are not authority.
        let os_profile = OsStr::new(r"C:\Users\fixed-native-user");
        let native =
            OsStr::new(r"C:\Users\fixed-native-user\AppData\Local\Packages\native profile+λ_1\AC");
        let mapped = ExpectedEnvironment::from_process_profile(root, os_profile, native).unwrap();
        assert_eq!(
            mapped.local_app_data,
            root.join(r"home\AppData\Local\Packages\native profile+λ_1\AC")
        );
        assert_eq!(mapped.temporary, mapped.local_app_data.join("Temp"));
        assert_eq!(mapped.temporary_alias, mapped.temporary);
        let unicode_root = OsStr::new(r"\\?\D:\fixed-λ-雪");
        let unicode_native =
            OsStr::new(r"D:\fixed-λ-雪\AppData\Local\Packages\native profile+λ_1\AC");
        assert_eq!(
            ExpectedEnvironment::from_process_profile(root, unicode_root, unicode_native).unwrap(),
            mapped
        );
        for candidate in [
            r"C:\Users\other-user\AppData\Local\Packages\native profile+λ_1\AC",
            r"C:\Users\fixed-native-user\AppData\Local-extra\Packages\native profile+λ_1\AC",
            r"C:\Users\fixed-native-user\redirected-local\Packages\native profile+λ_1\AC",
            r"C:\Users\fixed-native-user\AppData\Local\Packages\native\extra\AC",
            r"C:\Users\fixed-native-user\AppData\Local\Packages\native\LocalCache",
            r"C:\Users\fixed-native-user\AppData\Local\Packages\..\AC",
            r"C:\Users\fixed-native-user\AppData\Local\Packages\native:ads\AC",
            r"C:\Users\fixed-native-user\AppData\Local\Packages\native.\AC",
            r"C:\Users\fixed-native-user\AppData\Local\Packages\CON .txt\AC",
            r"\\server\share\Packages\native\AC",
        ] {
            assert!(
                ExpectedEnvironment::from_process_profile(root, os_profile, OsStr::new(candidate))
                    .is_err()
            );
        }
        assert!(
            ExpectedEnvironment::from_process_profile(
                Path::new(r"\\server\share"),
                os_profile,
                native
            )
            .is_err()
        );
        assert!(
            ExpectedEnvironment::from_process_profile(
                root,
                OsStr::new(r"C:\Users\fixed-native-user\.."),
                native
            )
            .is_err()
        );
        // The startup/private caller base cannot replace the OS profile root.
        assert!(
            ExpectedEnvironment::from_process_profile(
                root,
                root.join(r"home\AppData\Local").as_os_str(),
                native
            )
            .is_err()
        );
        let oversize_profile = format!(
            r"C:\Users\fixed-native-user\AppData\Local\Packages\{}\AC",
            "x".repeat(129)
        );
        assert!(
            ExpectedEnvironment::from_process_profile(
                root,
                os_profile,
                OsStr::new(&oversize_profile)
            )
            .is_err()
        );
        let mut frame = Vec::new();
        mapped.write_to(&mut frame).unwrap();
        assert_eq!(
            ExpectedEnvironment::read_from(frame.as_slice(), root).unwrap(),
            mapped
        );
    }

    #[test]
    fn ordinary_native_profile_component_confines_literal_windows_names() {
        let root = Path::new(r"C:\fixed-private\dc-axis-windows-psec-fixed");
        let maximum = "x".repeat(128);
        let oversized = "x".repeat(129);
        for name in [
            "public space",
            "public+$[fixture]",
            "publicé",
            "公開",
            ".public",
            maximum.as_str(),
        ] {
            let units: Vec<_> = name.encode_utf16().collect();
            assert!(ordinary_profile_component(&units));
            let folder = root
                .join(r"home\AppData\Local\Packages")
                .join(name)
                .join("AC");
            let expected =
                ExpectedEnvironment::from_native_folder(root, folder.as_os_str()).unwrap();
            assert_eq!(expected.local_app_data, folder); // preserve exact literal bytes
            let mut frame = Vec::new();
            expected.write_to(&mut frame).unwrap();
            assert_eq!(
                ExpectedEnvironment::read_from(frame.as_slice(), root).unwrap(),
                expected
            );
        }
        assert!(ordinary_profile_component(&[0xd83d, 0xde00]));
        for name in [
            "",
            ".",
            "..",
            "public.",
            "public ",
            "public/child",
            r"public\child",
            "public:ads",
            oversized.as_str(),
        ] {
            assert!(!ordinary_profile_component(
                &name.encode_utf16().collect::<Vec<_>>()
            ));
            let folder = root
                .join(r"home\AppData\Local\Packages")
                .join(name)
                .join("AC");
            assert!(ExpectedEnvironment::from_native_folder(root, folder.as_os_str()).is_err());
        }
        for unit in (0u16..=31)
            .chain(127..=159)
            .chain([60, 62, 34, 124, 63, 42])
        {
            assert!(!ordinary_profile_component(&[65, unit, 66]));
        }
        for invalid in [
            &[0xd800][..],
            &[0xdc00][..],
            &[0xd800, 65][..],
            &[0xd800, 0xd800, 0xdc00][..],
        ] {
            assert!(!ordinary_profile_component(invalid));
        }
        let mut devices = vec![
            "CON".to_owned(),
            "prn".to_owned(),
            "Aux".to_owned(),
            "NUL".to_owned(),
            "CLOCK$".to_owned(),
            "CONIN$".to_owned(),
            "CONOUT$".to_owned(),
        ];
        for prefix in ["COM", "LPT"] {
            for suffix in [
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '¹', '²', '³',
            ] {
                devices.push(format!("{prefix}{suffix}"));
            }
        }
        for device in devices {
            for ending in ["", ".public", " .public", "  .public.extra"] {
                let name = format!("{device}{ending}");
                assert!(!ordinary_profile_component(
                    &name.encode_utf16().collect::<Vec<_>>()
                ));
                let folder = root
                    .join(r"home\AppData\Local\Packages")
                    .join(name)
                    .join("AC");
                assert!(ExpectedEnvironment::from_native_folder(root, folder.as_os_str()).is_err());
            }
        }
    }

    #[test]
    fn native_environment_utf16_frame_roundtrips_and_refuses_tampering() {
        let root = Path::new(r"\\?\C:\fixed-λ-雪\dc-axis-windows-psec-fixed");
        let folder = root.join(r"home\AppData\Local\Packages\native-profile\AC");
        let value = ExpectedEnvironment::from_native_folder(root, folder.as_os_str()).unwrap();
        let mut bytes = Vec::new();
        value.write_to(&mut bytes).unwrap();
        assert_eq!(
            ExpectedEnvironment::read_from(bytes.as_slice(), root).unwrap(),
            value
        );
        for size in [0, 7, bytes.len() - 1] {
            assert!(ExpectedEnvironment::read_from(&bytes[..size], root).is_err());
        }
        let mut oversized = bytes.clone();
        oversized[8..12].copy_from_slice(&((MAX_UNITS + 1) as u32).to_le_bytes());
        assert!(ExpectedEnvironment::read_from(oversized.as_slice(), root).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ExpectedEnvironment::read_from(trailing.as_slice(), root).is_err());
        let mut nul = bytes.clone();
        nul[12..14].fill(0);
        assert!(ExpectedEnvironment::read_from(nul.as_slice(), root).is_err());
        let mut mismatch =
            ExpectedEnvironment::from_native_folder(root, folder.as_os_str()).unwrap();
        mismatch.temporary_alias = root.join("tmp");
        let mut bytes = Vec::new();
        mismatch.write_to(&mut bytes).unwrap();
        assert!(ExpectedEnvironment::read_from(bytes.as_slice(), root).is_err());
    }
}
