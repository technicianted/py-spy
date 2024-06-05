use std::collections::HashMap;

use anyhow::{Context, Error, Result};
use console::{style, Term};
use remoteprocess::{Pid, Process};

use crate::config::Config;
#[cfg(unwind)]
use crate::native_stack_trace::NativeStack;
use crate::stack_trace::StackTrace;

/// Lets you retrieve stack traces of a running python program
pub struct ProcSpy {
    pub pid: Pid,
    pub process: Process,
    pub config: Config,
    #[cfg(unwind)]
    pub native: Option<NativeStack>,
    pub short_filenames: HashMap<String, Option<String>>,
}

impl ProcSpy {
    /// Constructs a new ProcSpy object.
    pub fn new(pid: Pid, config: &Config) -> Result<ProcSpy, Error> {
        let process = remoteprocess::Process::new(pid)
            .context("Failed to open process - check if it is running.")?;

        // lock the process when loading up on freebsd (rather than locking
        // on every memory read). Needs done after getting python process info
        // because procmaps also tries to attach w/ ptrace on freebsd
        #[cfg(target_os = "freebsd")]
        let _lock = process.lock();

        #[cfg(unwind)]
        let native = if config.native {
            Some(NativeStack::new(pid, None, None)?)
        } else {
            None
        };

        Ok(ProcSpy {
            pid,
            process,
            #[cfg(unwind)]
            native,
            config: config.clone(),
            short_filenames: HashMap::new(),
        })
    }

    /// Creates a PythonSpy object, retrying up to max_retries times.
    /// Mainly useful for the case where the process is just started and
    /// symbols or the python interpreter might not be loaded yet.
    pub fn retry_new(pid: Pid, config: &Config, max_retries: u64) -> Result<ProcSpy, Error> {
        let mut retries = 0;
        loop {
            let err = match ProcSpy::new(pid, config) {
                Ok(mut process) => {
                    // verify that we can load a stack trace before returning success
                    match process.get_stack_traces() {
                        Ok(_) => return Ok(process),
                        Err(err) => err,
                    }
                }
                Err(err) => err,
            };

            // If we failed, retry a couple times before returning the last error
            retries += 1;
            if retries >= max_retries {
                return Err(err);
            }
            info!("Failed to connect to process, retrying. Error: {}", err);
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[cfg(not(unwind))]
    pub fn get_stack_traces(&mut self) -> Result<Vec<StackTrace>, Error> {
        warn!("Unwind support is disabled, so stack traces will be empty");

        Ok(vec![])
    }

    #[cfg(unwind)]
    pub fn get_stack_traces(&mut self) -> Result<Vec<StackTrace>, Error> {
        let mut traces = Vec::new();

        if let Some(native) = self.native.as_mut() {
            native.add_native_only_threads(&self.process, &mut traces)?;
        }

        Ok(traces)
    }
}

pub fn print_traces(pid: Pid, config: &Config, parent: Option<Pid>) -> Result<(), Error> {
    let mut process = ProcSpy::new(pid, config)?;
    if config.dump_json {
        let traces = process.get_stack_traces()?;
        println!("{}", serde_json::to_string_pretty(&traces)?);
        return Ok(());
    }

    println!(
        "Process {}: {}",
        style(process.pid).bold().yellow(),
        process.process.cmdline()?.join(" ")
    );

    if let Some(parentpid) = parent {
        let parentprocess = remoteprocess::Process::new(parentpid)?;
        println!(
            "Parent Process {}: {}",
            style(parentpid).bold().yellow(),
            parentprocess.cmdline()?.join(" ")
        );
    }
    println!();
    let traces = process.get_stack_traces()?;
    for trace in traces.iter().rev() {
        crate::dump::print_trace(trace, true);
        if config.subprocesses {
            for (childpid, parentpid) in process
                .process
                .child_processes()
                .expect("failed to get subprocesses")
            {
                let term = Term::stdout();
                let (_, width) = term.size();

                println!("\n{}", &style("-".repeat(width as usize)).dim());
                // child_processes() returns the whole process tree, since we're recursing here
                // though we could end up printing grandchild processes multiple times. Limit down
                // to just once
                if parentpid == pid {
                    print_traces(childpid, config, Some(parentpid))?;
                }
            }
        }
    }
    Ok(())
}
