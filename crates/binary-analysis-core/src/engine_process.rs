use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

const STDOUT_LIMIT: u64 = 32 * 1024 * 1024;
const STDERR_LIMIT: u64 = 256 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(25);

pub(crate) fn run_engine(command: &mut Command, timeout: Duration) -> Result<Output> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start reviewed radare2")?;
    let stdout = child.stdout.take().context("radare2 stdout pipe missing")?;
    let stderr = child.stderr.take().context("radare2 stderr pipe missing")?;
    let (send, receive) = mpsc::channel();
    let stdout_sender = send.clone();
    let stdout_reader = thread::spawn(move || {
        let result = read_output(stdout, STDOUT_LIMIT, "stdout");
        let _ = stdout_sender.send(
            result
                .as_ref()
                .map(|_| ())
                .map_err(|error| format!("{error:#}")),
        );
        result
    });
    let stderr_reader = thread::spawn(move || {
        let result = read_output(stderr, STDERR_LIMIT, "stderr");
        let _ = send.send(
            result
                .as_ref()
                .map(|_| ())
                .map_err(|error| format!("{error:#}")),
        );
        result
    });
    let started = Instant::now();
    let outcome = loop {
        if let Some(error) = receive.try_iter().find_map(Result::err) {
            break Err(anyhow::anyhow!(error));
        }
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => {}
            Err(error) => {
                break Err(anyhow::Error::new(error).context("read radare2 process status"))
            }
        }
        if started.elapsed() >= timeout {
            break Err(anyhow::anyhow!(
                "radare2 analysis timed out after {} seconds",
                timeout.as_secs()
            ));
        }
        thread::sleep(POLL_INTERVAL);
    };
    let mut failures = Vec::new();
    if outcome.is_err() {
        if let Err(error) = child.kill() {
            failures.push(format!("terminate radare2: {error}"));
        }
        if let Err(error) = child.wait() {
            failures.push(format!("reap radare2: {error}"));
        }
    }
    let stdout = join_output(stdout_reader, "stdout");
    let stderr = join_output(stderr_reader, "stderr");
    let status = match outcome {
        Ok(status) => Some(status),
        Err(error) => {
            failures.insert(0, format!("{error:#}"));
            None
        }
    };
    let stdout = match stdout {
        Ok(value) => Some(value),
        Err(error) => {
            failures.push(format!("{error:#}"));
            None
        }
    };
    let stderr = match stderr {
        Ok(value) => Some(value),
        Err(error) => {
            failures.push(format!("{error:#}"));
            None
        }
    };
    if !failures.is_empty() {
        bail!("{}", failures.join("; "));
    }
    Ok(Output {
        status: status.context("radare2 exit status missing")?,
        stdout: stdout.context("radare2 stdout missing")?,
        stderr: stderr.context("radare2 stderr missing")?,
    })
}

fn read_output(reader: impl Read, limit: u64, stream: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read radare2 {stream}"))?;
    if bytes.len() as u64 > limit {
        bail!("radare2 {stream} exceeds {limit} byte output limit");
    }
    Ok(bytes)
}

fn join_output(reader: thread::JoinHandle<Result<Vec<u8>>>, stream: &str) -> Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("radare2 {stream} reader panicked"))?
}

#[cfg(test)]
mod tests {
    use super::{run_engine, STDERR_LIMIT, STDOUT_LIMIT};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    fn python(script: &str) -> Command {
        let executable = if cfg!(windows) { "python" } else { "python3" };
        let mut command = Command::new(executable);
        command.args(["-c", script]).stdin(Stdio::null());
        command
    }

    #[test]
    fn drains_real_stdout_and_stderr_beyond_pipe_capacity() {
        let mut command =
            python("import os; os.write(1, b'x' * 1048576); os.write(2, b'e' * 131072)");
        let output =
            run_engine(&mut command, Duration::from_secs(10)).expect("drain actual command pipes");
        assert!(output.status.success());
        assert_eq!(output.stdout, vec![b'x'; 1048576]);
        assert_eq!(output.stderr, vec![b'e'; 131072]);
    }

    #[test]
    fn output_limits_terminate_the_actual_child() {
        for (fd, limit) in [(1, STDOUT_LIMIT), (2, STDERR_LIMIT)] {
            let script = format!(
                "import os; os.write({fd}, b'x' * {});\nwhile True: pass",
                limit + 1
            );
            let started = Instant::now();
            let error = run_engine(&mut python(&script), Duration::from_secs(10))
                .expect_err("actual oversized pipe fails");
            assert!(format!("{error:#}").contains("byte output limit"));
            assert!(started.elapsed() < Duration::from_secs(5));
        }
    }

    #[test]
    fn timeout_terminates_and_reaps_real_child_with_open_pipes() {
        let started = Instant::now();
        let error = run_engine(&mut python("while True: pass"), Duration::from_millis(100))
            .expect_err("real command deadline");
        assert!(format!("{error:#}").contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
