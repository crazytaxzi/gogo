'use strict';

const fs = require('fs');
const { spawnSync } = require('child_process');

function createMutationFirewall(options = {}) {
  const mode = String(
    options.mode ||
    process.env.SENTIONCE_MUTATION_FIREWALL_MODE ||
    'off'
  ).trim().toLowerCase();

  const exe = options.exe ||
    process.env.SENTIONCE_MUTATION_FIREWALL_EXE ||
    'E:\\SentionceRecovery\\MutationFirewall\\publish\\SentionceMutationFirewall.exe';

  const policy = options.policy ||
    process.env.SENTIONCE_MUTATION_FIREWALL_POLICY ||
    'E:\\SentionceRecovery\\MutationFirewall\\policy.json';

  const enabled = mode !== 'off';
  const required = mode === 'required';

  function unavailable(message) {
    if (required) throw new Error('MUTATION_FIREWALL_UNAVAILABLE: ' + message);
    return { enabled:false, unavailable:true, message };
  }

  function invoke(args, opts = {}) {
    if (!enabled) return { enabled:false, bypassed:true };
    if (!fs.existsSync(exe)) return unavailable('executable not found: ' + exe);
    if (!fs.existsSync(policy)) return unavailable('policy not found: ' + policy);

    const fullArgs = [...args, '--policy', policy];
    const r = spawnSync(exe, fullArgs, {
      encoding:'utf8',
      windowsHide:true,
      shell:false,
      timeout:Number(opts.timeoutMs || 120000),
      maxBuffer:4 * 1024 * 1024,
    });

    if (r.error) throw new Error('MUTATION_FIREWALL_ERROR: ' + r.error.message);

    const stdout = String(r.stdout || '').trim();
    let parsed = null;
    if (stdout) {
      try { parsed = JSON.parse(stdout); }
      catch {
        throw new Error('MUTATION_FIREWALL_ERROR: invalid JSON response: ' + stdout.slice(0, 500));
      }
    }

    return {
      exitCode:r.status,
      stderr:String(r.stderr || '').trim(),
      result:parsed,
    };
  }

  function throwDecision(prefix, response, fallback) {
    const result = response && response.result;
    const reasons = result && Array.isArray(result.reasons)
      ? result.reasons.join(' | ')
      : result && result.decision && Array.isArray(result.decision.reasons)
        ? result.decision.reasons.join(' | ')
        : result && result.message
          ? String(result.message)
          : response && response.stderr
            ? response.stderr
            : fallback;
    throw new Error(prefix + ': ' + reasons);
  }

  function status() {
    const r = invoke(['status']);
    if (!enabled) return { enabled:false };
    if (!r.result || r.exitCode !== 0) throwDecision('MUTATION_FIREWALL_ERROR', r, 'status failed');
    return r.result;
  }

  function evaluatePath(target) {
    const r = invoke(['evaluate', '--path', String(target)]);
    if (!enabled) return { allowed:true, firewallDisabled:true };
    if (!r.result || !r.result.decision) throwDecision('MUTATION_FIREWALL_ERROR', r, 'path evaluation failed');
    if (!r.result.decision.allowed) {
      throwDecision('MUTATION_FIREWALL_BLOCKED', r, 'path denied');
    }
    return r.result.decision;
  }

  function enforceCommand(command, context = 'command') {
    if (!enabled) return { rawExecutionAllowed:true, firewallDisabled:true };
    const r = invoke(['scan-command', '--command', String(command)]);
    if (!r.result) throwDecision('MUTATION_FIREWALL_ERROR', r, 'command scan failed');

    if (r.result.blocked) {
      const findings = Array.isArray(r.result.findings)
        ? r.result.findings.map(x => x.category + ': ' + x.explanation).join(' | ')
        : 'critical command';
      throw new Error('MUTATION_FIREWALL_BLOCKED: ' + context + ': ' + findings);
    }

    if (r.result.requiresBroker) {
      const findings = Array.isArray(r.result.findings)
        ? r.result.findings.map(x => x.category + ': ' + x.explanation).join(' | ')
        : 'mutation requires broker';
      throw new Error('MUTATION_BROKER_REQUIRED: ' + context + ': ' + findings);
    }

    return r.result;
  }

  function quarantine(target, reason = 'GoGoMCP file.delete') {
    const r = invoke(['quarantine', '--path', String(target), '--reason', String(reason)]);
    if (!enabled) throw new Error('MUTATION_FIREWALL_UNAVAILABLE: quarantine requires enabled firewall');
    if (!r.result || r.exitCode !== 0 || !r.result.quarantined) {
      throwDecision('MUTATION_FIREWALL_BLOCKED', r, 'quarantine failed');
    }
    return r.result;
  }

  function replace(target, source, reason = 'GoGoMCP file.write') {
    const r = invoke(['replace', '--target', String(target), '--source', String(source), '--reason', String(reason)]);
    if (!enabled) throw new Error('MUTATION_FIREWALL_UNAVAILABLE: replace requires enabled firewall');
    if (!r.result || r.exitCode !== 0 || !r.result.ok) {
      throwDecision('MUTATION_FIREWALL_BLOCKED', r, 'replace failed');
    }
    return r.result;
  }

  function move(source, destination, reason = 'GoGoMCP file.move') {
    const r = invoke(['move', '--source', String(source), '--destination', String(destination), '--reason', String(reason)]);
    if (!enabled) throw new Error('MUTATION_FIREWALL_UNAVAILABLE: move requires enabled firewall');
    if (!r.result || r.exitCode !== 0 || !r.result.ok) {
      throwDecision('MUTATION_FIREWALL_BLOCKED', r, 'move failed');
    }
    return r.result;
  }

  return {
    enabled,
    required,
    exe,
    policy,
    status,
    evaluatePath,
    enforceCommand,
    quarantine,
    replace,
    move,
  };
}

module.exports = { createMutationFirewall };
