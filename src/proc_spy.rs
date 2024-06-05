#[cfg(windows)]
use regex::RegexBuilder;
use std::collections::HashMap;
#[cfg(all(target_os = "linux", unwind))]
use std::collections::HashSet;
#[cfg(all(target_os = "linux", unwind))]
use std::iter::FromIterator;
use std::path::Path;

use anyhow::{Context, Error, Result};
use remoteprocess::{Pid, Process, ProcessMemory, Tid};

use crate::config::{Config, LockingStrategy};
#[cfg(unwind)]
use crate::native_stack_trace::NativeStack;
use crate::python_bindings::{
    v2_7_15, v3_10_0, v3_11_0, v3_3_7, v3_5_5, v3_6_6, v3_7_0, v3_8_0, v3_9_5,
};
use crate::python_data_access::format_variable;
use crate::python_interpreters::{InterpreterState, ThreadState};
use crate::python_process_info::{
    get_interpreter_address, get_python_version, get_threadstate_address, PythonProcessInfo,
};
use crate::python_threading::thread_name_lookup;
use crate::stack_trace::{get_gil_threadid, get_stack_trace, StackTrace};
use crate::version::Version;

/// Lets you retrieve stack traces of a running python program
pub struct ProcSpy {
    pub pid: Pid,
    pub process: Process,
    pub config: Config,
    #[cfg(unwind)]
    pub native: Option<NativeStack>,
    pub short_filenames: HashMap<String, Option<String>>,
    #[cfg(target_os = "linux")]
    pub dockerized: bool,
}

impl ProcSpy {
    /// Constructs a new ProcSpy object.
    pub fn new(pid: Pid, config: &Config) -> Result<PythonSpy, Error> {
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
            #[cfg(target_os = "linux")]
            dockerized: python_info.dockerized,
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

    /// Gets a StackTrace for each thread in the current process
    pub fn get_stack_traces(&mut self) -> Result<Vec<StackTrace>, Error> {
        let mut traces = Vec::new();

        #[cfg(unwind)]
        if self.config.native_all {
            if let Some(native) = self.native.as_mut() {
                native.add_native_only_threads(&self.process, &mut traces)?;
            }
        }
    }

    // heuristic fallback for determining if a thread is active, used
    // when we don't have the ability to get the thread information from the OS
    fn _heuristic_is_thread_idle(&self, trace: &StackTrace) -> bool {
        let frames = &trace.frames;
        if frames.is_empty() {
            // we could have 0 python frames, but still be active running native
            // code.
            false
        } else {
            let frame = &frames[0];
            (frame.name == "wait" && frame.filename.ends_with("threading.py"))
                || (frame.name == "select" && frame.filename.ends_with("selectors.py"))
                || (frame.name == "poll"
                    && (frame.filename.ends_with("asyncore.py")
                        || frame.filename.contains("zmq")
                        || frame.filename.contains("gevent")
                        || frame.filename.contains("tornado")))
        }
    }

    #[cfg(windows)]
    fn _get_os_thread_id<I: InterpreterState>(
        &mut self,
        python_thread_id: u64,
        _interp: &I,
    ) -> Result<Option<Tid>, Error> {
        Ok(Some(python_thread_id as Tid))
    }

    #[cfg(target_os = "macos")]
    fn _get_os_thread_id<I: InterpreterState>(
        &mut self,
        python_thread_id: u64,
        _interp: &I,
    ) -> Result<Option<Tid>, Error> {
        // If we've already know this threadid, we're good
        if let Some(thread_id) = self.python_thread_ids.get(&python_thread_id) {
            return Ok(Some(*thread_id));
        }

        for thread in self.process.threads()?.iter() {
            // ok, this is crazy pants. is this 224 constant right?  Is this right for all versions of OSX? how is this determined?
            // is this correct for all versions of python? Why does this even work?
            let current_handle = thread.thread_handle()? - 224;
            self.python_thread_ids.insert(current_handle, thread.id()?);
        }

        if let Some(thread_id) = self.python_thread_ids.get(&python_thread_id) {
            return Ok(Some(*thread_id));
        }
        Ok(None)
    }

    #[cfg(all(target_os = "linux", not(unwind)))]
    fn _get_os_thread_id<I: InterpreterState>(
        &mut self,
        _python_thread_id: u64,
        _interp: &I,
    ) -> Result<Option<Tid>, Error> {
        Ok(None)
    }

    #[cfg(all(target_os = "linux", unwind))]
    fn _get_os_thread_id<I: InterpreterState>(
        &mut self,
        python_thread_id: u64,
        interp: &I,
    ) -> Result<Option<Tid>, Error> {
        // in nonblocking mode, we can't get the threadid reliably (method here requires reading the RBX
        // register which requires a ptrace attach). fallback to heuristic thread activity here
        if self.config.blocking == LockingStrategy::NonBlocking {
            return Ok(None);
        }

        // likewise this doesn't yet work for profiling processes running inside docker containers from the host os
        if self.dockerized {
            return Ok(None);
        }

        // If we've already know this threadid, we're good
        if let Some(thread_id) = self.python_thread_ids.get(&python_thread_id) {
            return Ok(Some(*thread_id));
        }

        // Get a list of all the python thread ids
        let mut all_python_threads = HashSet::new();
        let mut threads = interp.head();
        while !threads.is_null() {
            let thread = self
                .process
                .copy_pointer(threads)
                .context("Failed to copy PyThreadState")?;
            let current = thread.thread_id();
            all_python_threads.insert(current);
            threads = thread.next();
        }

        let processed_os_threads: HashSet<Tid> =
            HashSet::from_iter(self.python_thread_ids.values().copied());

        let unwinder = self.process.unwinder()?;

        // Try getting the pthread_id from the native stack registers for threads we haven't looked up yet
        for thread in self.process.threads()?.iter() {
            let threadid = thread.id()?;
            if processed_os_threads.contains(&threadid) {
                continue;
            }

            match self._get_pthread_id(&unwinder, thread, &all_python_threads) {
                Ok(pthread_id) => {
                    if pthread_id != 0 {
                        self.python_thread_ids.insert(pthread_id, threadid);
                    }
                }
                Err(e) => {
                    warn!("Failed to get get_pthread_id for {}: {}", threadid, e);
                }
            };
        }

        // we can't get the python threadid for the main thread from registers,
        // so instead assign the main threadid (pid) to the missing python thread
        if !processed_os_threads.contains(&self.pid) {
            let mut unknown_python_threadids = HashSet::new();
            for python_thread_id in all_python_threads.iter() {
                if !self.python_thread_ids.contains_key(python_thread_id) {
                    unknown_python_threadids.insert(*python_thread_id);
                }
            }

            if unknown_python_threadids.len() == 1 {
                let python_thread_id = *unknown_python_threadids.iter().next().unwrap();
                self.python_thread_ids.insert(python_thread_id, self.pid);
            } else {
                warn!("failed to get python threadid for main thread!");
            }
        }

        if let Some(thread_id) = self.python_thread_ids.get(&python_thread_id) {
            return Ok(Some(*thread_id));
        }
        info!("failed looking up python threadid for {}. known python_thread_ids {:?}. all_python_threads {:?}",
            python_thread_id, self.python_thread_ids, all_python_threads);
        Ok(None)
    }

    #[cfg(all(target_os = "linux", unwind))]
    pub fn _get_pthread_id(
        &self,
        unwinder: &remoteprocess::Unwinder,
        thread: &remoteprocess::Thread,
        threadids: &HashSet<u64>,
    ) -> Result<u64, Error> {
        let mut pthread_id = 0;

        let mut cursor = unwinder.cursor(thread)?;
        while let Some(_) = cursor.next() {
            // the pthread_id is usually in the top-level frame of the thread, but on some configs
            // can be 2nd level. Handle this by taking the top-most rbx value that is one of the
            // pthread_ids we're looking for
            if let Ok(bx) = cursor.bx() {
                if bx != 0 && threadids.contains(&bx) {
                    pthread_id = bx;
                }
            }
        }

        Ok(pthread_id)
    }

    #[cfg(target_os = "freebsd")]
    fn _get_os_thread_id<I: InterpreterState>(
        &mut self,
        _python_thread_id: u64,
        _interp: &I,
    ) -> Result<Option<Tid>, Error> {
        Ok(None)
    }

    fn _get_python_thread_name(&mut self, python_thread_id: u64) -> Option<String> {
        match self.python_thread_names.get(&python_thread_id) {
            Some(thread_name) => Some(thread_name.clone()),
            None => {
                self.python_thread_names = thread_name_lookup(self).unwrap_or_default();
                self.python_thread_names.get(&python_thread_id).cloned()
            }
        }
    }

    /// We want to display filenames without the boilerplate of the python installation
    /// directory etc. This function looks only includes paths inside a python
    /// package or subpackage, and not the path the package is installed at
    fn shorten_filename(&mut self, filename: &str) -> Option<String> {
        // if the user requested full filenames, skip shortening
        if self.config.full_filenames {
            return Some(filename.to_string());
        }

        // if we have figured out the short filename already, use it
        if let Some(short) = self.short_filenames.get(filename) {
            return short.clone();
        }

        // on linux the process could be running in docker, access the filename through procfs
        #[cfg(target_os = "linux")]
        let filename_storage;

        #[cfg(target_os = "linux")]
        let filename = if self.dockerized {
            filename_storage = format!("/proc/{}/root{}", self.pid, filename);
            if Path::new(&filename_storage).exists() {
                &filename_storage
            } else {
                filename
            }
        } else {
            filename
        };

        // only include paths that include an __init__.py
        let mut path = Path::new(filename);
        while let Some(parent) = path.parent() {
            path = parent;
            if !parent.join("__init__.py").exists() {
                break;
            }
        }

        // remove the parent prefix and convert to an optional string
        let shortened = Path::new(filename)
            .strip_prefix(path)
            .ok()
            .map(|p| p.to_string_lossy().to_string());

        self.short_filenames
            .insert(filename.to_owned(), shortened.clone());
        shortened
    }
}
