use std::process::Command;

pub fn run_tool(argument: &str) -> std::io::Result<std::process::ExitStatus> {
    Command::new("helper-tool").arg(argument).status()
}
