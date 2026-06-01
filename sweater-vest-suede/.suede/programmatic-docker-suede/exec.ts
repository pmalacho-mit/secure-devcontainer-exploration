/// <reference types="node" />
import { execFile } from "node:child_process";
import { promisify } from "node:util";

/** Promisified version of `child_process.execFile`. */
export const execFileAsync = promisify(execFile);

/**
 * Run an executable with arguments, returning stdout and stderr.
 * @param command - The executable to run. Example: "docker"
 * @param args - Arguments to pass to the executable. Example: ["run", "--rm", "node:20"]
 * @param cwd - Working directory for the process. Default: process.cwd()
 */
export const runCmd = async (command: string, args: string[], cwd?: string) => {
  const { stdout, stderr } = await execFileAsync(command, args, {
    cwd,
    maxBuffer: 16 * 1024 * 1024,
  });
  return { stdout, stderr };
};

export type CmdResult = Awaited<ReturnType<typeof runCmd>>;
