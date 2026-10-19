// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! Explicit native-PSEC adapter over the same Owner and protocol state machine.
//! Initial grant floor: only descendants of one protected held CWD subtree,
//! plus the exact immutable private payload copy. Arbitrary host grants refuse.
use crate::owner::{Engine, Pipes, Prepared, Process};
use crate::windows_bootstrap::Capabilities;
use crate::windows_io::Pipe;
use crate::wire::{Preparation, ProtocolError, Result};
use mxc_sdk::v1::{
    ContainerRequest, Containment, FilesystemPolicy, NetworkAction, NetworkEgressPolicy,
    NetworkIngressPolicy, NetworkPolicy, OwnedPsecProcess, OwnedWindowsStdio,
    PreparedOwnedWindowsPsec, configs::ProcessContainerConfig,
};
use std::ffi::OsString;
use std::fs::File;

pub struct WindowsEngine {
    capabilities: Option<Capabilities>,
}
impl WindowsEngine {
    pub fn new(capabilities: Capabilities) -> Self {
        Self {
            capabilities: Some(capabilities),
        }
    }
}
struct WindowsPrepared(PreparedOwnedWindowsPsec);
struct WindowsProcess {
    process: OwnedPsecProcess,
    pipes: Option<Pipes>,
}
impl Engine for WindowsEngine {
    fn prepare(&mut self, plan: &Preparation) -> Result<Box<dyn Prepared>> {
        let capabilities = self.capabilities.take().ok_or(ProtocolError)?;
        capabilities.bind(plan)?;
        let mut files = capabilities.into_objects().into_iter();
        let payload = File::from(files.next().ok_or(ProtocolError)?.into_handle()?);
        let cwd = File::from(files.next().ok_or(ProtocolError)?.into_handle()?);
        let mut readonly = Vec::with_capacity(plan.filesystem.read.len());
        let mut readwrite = Vec::with_capacity(plan.filesystem.write.len());
        for _ in &plan.filesystem.read {
            readonly.push(File::from(
                files.next().ok_or(ProtocolError)?.into_handle()?,
            ));
        }
        for _ in &plan.filesystem.write {
            readwrite.push(File::from(
                files.next().ok_or(ProtocolError)?.into_handle()?,
            ));
        }
        if files.next().is_some() {
            return Err(ProtocolError);
        }
        let mut request = ContainerRequest::new("");
        request.containment = Containment::ProcessContainer(ProcessContainerConfig::default());
        request.filesystem = Some(FilesystemPolicy {
            readonly_paths: plan.filesystem.read.clone(),
            readwrite_paths: plan.filesystem.write.clone(),
            denied_paths: Vec::new(),
            clear_policy_on_exit: Some(true),
        });
        request.network = Some(NetworkPolicy {
            egress: Some(NetworkEgressPolicy {
                default: Some(NetworkAction::Deny),
                ..Default::default()
            }),
            ingress: Some(NetworkIngressPolicy {
                default: Some(NetworkAction::Deny),
                host_loopback: Some(NetworkAction::Deny),
            }),
            runtime_config: None,
        });
        request.timeout_ms = Some(plan.timeout_ms);
        request.working_directory = Some(plan.workdir.clone());
        request.environment = Some(
            plan.environment
                .iter()
                .map(|value| (value.name.clone(), value.value.clone()))
                .collect(),
        );
        request.inherit_default_environment = Some(false);
        // This constructor validates actual granted access, protected root DACL,
        // exact held DOS-name correlation and no-follow root-relative FileIDs.
        // None of the JSON path strings is reopened as an arbitrary host path.
        let prepared = PreparedOwnedWindowsPsec::new(
            request,
            plan.argv.iter().map(OsString::from).collect(),
            payload,
            cwd,
            readonly,
            readwrite,
        )
        .map_err(|_| ProtocolError)?;
        Ok(Box::new(WindowsPrepared(prepared)))
    }
}
impl Prepared for WindowsPrepared {
    fn launch(self: Box<Self>) -> Result<Box<dyn Process>> {
        let (input, child_input) = Pipe::workload_pair(true).map_err(|_| ProtocolError)?;
        let (output, child_output) = Pipe::workload_pair(false).map_err(|_| ProtocolError)?;
        let (error, child_error) = Pipe::workload_pair(false).map_err(|_| ProtocolError)?;
        let process = self
            .0
            .spawn(
                OwnedWindowsStdio::new(child_input, child_output, child_error)
                    .map_err(|_| ProtocolError)?,
            )
            .map_err(|_| ProtocolError)?;
        Ok(Box::new(WindowsProcess {
            process,
            pipes: Some(Pipes {
                input: Some(input),
                output: Some(output),
                error: Some(error),
            }),
        }))
    }
}
impl Process for WindowsProcess {
    fn take_pipes(&mut self) -> Result<Pipes> {
        self.pipes.take().ok_or(ProtocolError)
    }
    fn try_wait(&mut self) -> Result<Option<i32>> {
        self.process.try_wait().map_err(|_| ProtocolError)
    }
    fn stop(&mut self) -> Result<()> {
        self.process.stop().map_err(|_| ProtocolError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    #[test]
    fn native_sdk_owned_stdio_accepts_only_the_fixed_sync_child_endpoints() {
        let (mut input, child_input) = Pipe::workload_pair(true).unwrap();
        let (mut output, child_output) = Pipe::workload_pair(false).unwrap();
        let (mut error, child_error) = Pipe::workload_pair(false).unwrap();
        let endpoints = OwnedWindowsStdio::new(child_input, child_output, child_error).unwrap();
        drop(endpoints);
        let deadline = Instant::now() + Duration::from_millis(500);
        input.close(deadline).unwrap();
        output.close(deadline).unwrap();
        error.close(deadline).unwrap();
    }
}
