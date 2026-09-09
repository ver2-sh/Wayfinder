import { spawn } from 'node:child_process';
import { join } from 'node:path';

export interface ExecInput {
  command: string;
  cwd?: string;
  timeout: number;
  env?: Record<string, string>;
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: string | null;
  timedOut: boolean;
  error?: string;
}

const outputLimit = 1024 * 1024;

export function execute(input: ExecInput, signal: AbortSignal): Promise<ExecResult> {
  return new Promise((resolve) => {
    const result: ExecResult = { stdout: '', stderr: '', exitCode: null, signal: null, timedOut: false };
    if (signal.aborted) return resolve({ ...result, error: 'Execution cancelled.' });
    // Windows environment keys are case-insensitive. Merge accordingly.
    const env: NodeJS.ProcessEnv = { ...process.env };
    for (const [key, value] of Object.entries(input.env ?? {})) {
      if (process.platform === 'win32') {
        for (const existing of Object.keys(env)) {
          if (existing.toLowerCase() === key.toLowerCase()) delete env[existing];
        }
      }
      env[key] = value;
    }
    const child = spawn(input.command, {
      shell: true, cwd: input.cwd, env, windowsHide: true,
      detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'],
    });
    let termination: Promise<void> | undefined;
    function terminate(): Promise<void> {
      return termination ??= new Promise<void>((done) => {
        if (!child.pid) return done();
        if (process.platform === 'win32') {
          const killer = spawn(join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'taskkill.exe'),
            ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
          killer.on('error', (error) => {
            result.error = `Process tree termination failed: ${error.message}`;
            child.kill('SIGKILL');
            done();
          });
          killer.on('close', (code) => {
            if (code !== 0 && child.exitCode === null && child.signalCode === null) {
              result.error = 'Process tree termination failed.';
              child.kill('SIGKILL');
            }
            done();
          });
        } else {
          try { process.kill(-child.pid, 'SIGKILL'); }
          catch (error) {
            if ((error as NodeJS.ErrnoException).code !== 'ESRCH') result.error = `Process tree termination failed: ${(error as Error).message}`;
          }
          done();
        }
      });
    }
    const timer = setTimeout(() => { result.timedOut = true; void terminate(); }, input.timeout);
    const abort = () => { result.error = 'Execution cancelled.'; void terminate(); };
    signal.addEventListener('abort', abort, { once: true });
    const chunks: Record<'stdout' | 'stderr', Buffer[]> = { stdout: [], stderr: [] };
    const sizes = { stdout: 0, stderr: 0 };
    for (const stream of ['stdout', 'stderr'] as const) {
      child[stream].on('data', (data: Buffer) => {
        const remaining = outputLimit - sizes[stream];
        if (remaining > 0) chunks[stream].push(data.subarray(0, remaining));
        sizes[stream] += Math.min(remaining, data.length);
        if (data.length > remaining) {
          result.error = `${stream} exceeded the 1 MiB output limit; output is truncated.`;
          void terminate();
        }
      });
    }
    child.on('error', (error) => { result.error = `Execution failed: ${error.message}`; });
    child.on('close', async (code, exitSignal) => {
      clearTimeout(timer);
      signal.removeEventListener('abort', abort);
      await termination;
      result.stdout = Buffer.concat(chunks.stdout).toString('utf8');
      result.stderr = Buffer.concat(chunks.stderr).toString('utf8');
      result.exitCode = code;
      result.signal = exitSignal;
      resolve(result);
    });
  });
}
