// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! Fixed contributor protocol. Parsing and formatting never load a DLL.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedDll {
    User32,
    Gdi32,
    Shell32,
}

pub const CASES: [FixedDll; 3] = [FixedDll::User32, FixedDll::Gdi32, FixedDll::Shell32];

impl FixedDll {
    pub fn selector(self) -> &'static str {
        match self {
            Self::User32 => "--load-user32",
            Self::Gdi32 => "--load-gdi32",
            Self::Shell32 => "--load-shell32",
        }
    }

    pub fn from_selector(value: &std::ffi::OsStr) -> Option<Self> {
        CASES.into_iter().find(|case| value == case.selector())
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::User32 => "user32",
            Self::Gdi32 => "gdi32",
            Self::Shell32 => "shell32",
        }
    }

    pub fn dll_name(self) -> &'static str {
        match self {
            Self::User32 => "user32.dll",
            Self::Gdi32 => "gdi32.dll",
            Self::Shell32 => "shell32.dll",
        }
    }

    pub fn start_marker(self) -> String {
        format!("FIXED_DLL_START:{}\n", self.label())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadResult {
    Loaded,
    ReturnedError(u32),
}

impl LoadResult {
    pub fn marker(self, case: FixedDll) -> String {
        match self {
            Self::Loaded => format!("FIXED_DLL_RETURN:{}:loaded\n", case.label()),
            Self::ReturnedError(code) => {
                format!("FIXED_DLL_RETURN:{}:error:{code}\n", case.label())
            }
        }
    }

    pub fn parse(case: FixedDll, output: &str) -> Option<Self> {
        let suffix = output.strip_prefix(&case.start_marker())?;
        if suffix == Self::Loaded.marker(case) {
            return Some(Self::Loaded);
        }
        let prefix = format!("FIXED_DLL_RETURN:{}:error:", case.label());
        let code = suffix.strip_prefix(&prefix)?.strip_suffix('\n')?;
        // Exact, bounded canonical decimal: no signs, padding, second line or
        // a false error-zero report. A DLL name/path is never input here.
        if code.is_empty() || code.len() > 10 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let parsed = code.parse::<u32>().ok()?;
        if parsed == 0 || parsed.to_string() != code {
            return None;
        }
        Some(Self::ReturnedError(parsed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_dll_selectors_never_accept_an_arbitrary_module_or_path() {
        for case in CASES {
            assert_eq!(
                FixedDll::from_selector(case.selector().as_ref()),
                Some(case)
            );
            assert_eq!(case.dll_name(), format!("{}.dll", case.label()));
        }
        for value in [
            "",
            "user32.dll",
            "--load-user32.dll",
            "C:\\user32.dll",
            "--load-tdh",
            "--load-USER32",
            "--load-shell32\0",
        ] {
            assert_eq!(FixedDll::from_selector(value.as_ref()), None);
        }
    }

    #[test]
    fn exact_dll_markers_distinguish_returned_error_from_success() {
        for case in CASES {
            for result in [
                LoadResult::Loaded,
                LoadResult::ReturnedError(1114),
                LoadResult::ReturnedError(u32::MAX),
            ] {
                let output = case.start_marker() + &result.marker(case);
                assert_eq!(LoadResult::parse(case, &output), Some(result));
                for other in CASES.into_iter().filter(|other| *other != case) {
                    assert_eq!(LoadResult::parse(other, &output), None);
                }
                for changed in [
                    output.trim_end().to_string(),
                    output.clone() + "extra\n",
                    format!("x{output}"),
                    output.replace('\n', "\r\n"),
                ] {
                    assert_eq!(LoadResult::parse(case, &changed), None);
                }
            }
            for code in [
                "0",
                "00",
                "01114",
                "+1114",
                "-1",
                "4294967296",
                "1114\nextra",
                "1114\0",
            ] {
                let output = case.start_marker()
                    + &format!("FIXED_DLL_RETURN:{}:error:{code}\n", case.label());
                assert_eq!(LoadResult::parse(case, &output), None);
            }
        }
    }
}
