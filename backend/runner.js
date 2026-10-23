const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const MAX_OUTPUT = 20000; // characters captured per stream, to bound memory use

function run(cmd, args, opts) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(cmd, args, opts);
    } catch (err) {
      resolve({ code: null, signal: null, stdout: '', stderr: String(err), killedForTimeout: false });
      return;
    }
    let stdout = '';
    let stderr = '';
    let killedForTimeout = false;
    const timer = setTimeout(() => {
      killedForTimeout = true;
      try { child.kill('SIGKILL'); } catch (e) { /* already gone */ }
    }, opts.timeoutMs || 15000);

    child.stdout.on('data', (b) => { if (stdout.length < MAX_OUTPUT) stdout += b.toString(); });
    child.stderr.on('data', (b) => { if (stderr.length < MAX_OUTPUT) stderr += b.toString(); });

    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, stdout, stderr, killedForTimeout });
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ code: null, signal: null, stdout, stderr: stderr + '\n' + String(err), killedForTimeout: false });
    });
  });
}

function detectSanitizer(stderr) {
  const markers = [
    [/AddressSanitizer/i, 'AddressSanitizer'],
    [/ThreadSanitizer/i, 'ThreadSanitizer'],
    [/UndefinedBehaviorSanitizer/i, 'UndefinedBehaviorSanitizer'],
    [/runtime error:/i, 'UndefinedBehaviorSanitizer'],
  ];
  for (const [re, name] of markers) {
    if (re.test(stderr)) return name;
  }
  return null;
}

function summarize(stderr, lines) {
  return stderr.split('\n').slice(0, lines || 18).join('\n');
}

async function runDemo(meta, variant) {
  const srcFile = path.join(meta.dir, variant === 'fixed' ? 'fixed.c' : 'vulnerable.c');
  const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'demo-'));
  const binPath = path.join(tmpBase, 'a.out');

  const sanitize =
    (variant === 'fixed' ? meta.sanitize_fixed : meta.sanitize_vulnerable) ||
    meta.sanitize ||
    'address,undefined';
  const extraCflags = meta.extra_cflags || [];
  const compileArgs = [
    '-g', '-O0', '-fno-omit-frame-pointer',
    '-fsanitize=' + sanitize,
    ...extraCflags,
    '-o', binPath, srcFile,
  ];

  const compile = await run('gcc', compileArgs, { timeoutMs: 20000 });
  if (compile.code !== 0) {
    try { fs.rmSync(tmpBase, { recursive: true, force: true }); } catch (e) { /* ignore */ }
    return {
      stage: 'compile',
      success: false,
      exitCode: compile.code,
      timedOut: compile.killedForTimeout,
      durationMs: 0,
      stdout: '',
      stderr: compile.stderr || compile.stdout,
      sanitizerIssue: null,
      sanitizerSummary: null,
    };
  }

  const timeoutS = meta.timeout_s || 5;
  // NOTE: ulimit -v (virtual address space) is NOT used here. AddressSanitizer and
  // ThreadSanitizer reserve a very large virtual address range for their shadow memory at
  // startup (terabytes on x86_64) even though almost none of it is ever touched; a tight
  // ulimit -v makes that reservation fail and aborts EVERY sanitized binary immediately,
  // vulnerable and fixed alike. Real memory use is bounded instead via ASan's own
  // hard_rss_limit_mb, which tracks actual resident memory, not reserved address space.
  const rssLimitMb = meta.rss_limit_mb || 512;
  const sanitizerEnv = sanitize.includes('address')
    ? {
        // allocator_may_return_null=1: a too-large or failed allocation returns NULL like a
        // normal malloc would, instead of ASan aborting the process itself. This keeps a
        // demo's own "if (!p) ..." error handling the thing that's actually being
        // demonstrated, rather than ASan's internal allocator guard pre-empting it.
        ASAN_OPTIONS: `hard_rss_limit_mb=${rssLimitMb}:detect_leaks=0:exitcode=1:allocator_may_return_null=1`,
      }
    : {};
  const shellCmd = 'exec timeout -k 1 ' + timeoutS + 's "' + binPath + '"';

  const t0 = Date.now();
  const exec = await run('bash', ['-c', shellCmd], {
    timeoutMs: (timeoutS + 3) * 1000,
    cwd: tmpBase,
    env: { ...process.env, ...sanitizerEnv },
  });
  const durationMs = Date.now() - t0;

  try { fs.rmSync(tmpBase, { recursive: true, force: true }); } catch (e) { /* ignore */ }

  const sanitizerIssue = detectSanitizer(exec.stderr);
  const timedOut = exec.killedForTimeout || exec.code === 124;

  return {
    stage: 'run',
    success: exec.code === 0,
    exitCode: exec.code,
    signal: exec.signal,
    timedOut,
    durationMs,
    stdout: exec.stdout,
    stderr: exec.stderr,
    sanitizerIssue,
    sanitizerSummary: sanitizerIssue ? summarize(exec.stderr) : null,
  };
}

module.exports = { runDemo };
