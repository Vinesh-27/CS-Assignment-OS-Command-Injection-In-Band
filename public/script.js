/**
 * Network Diagnostic Tool - Frontend Controller
 * Cyber Security Lab: OS Command Injection (In-band) vs Parameterized Execution
 *
 * Implements:
 * 1. Safe text rendering using textContent (Strictly NO innerHTML for command outputs)
 * 2. Status handshake with /api/status
 * 3. Execution handling for Secured (/api/ping/secured) and Vulnerable (/api/ping/vulnerable)
 * 4. Terminal output formatting, execution metrics, and educational analysis callout
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const form = document.getElementById('diagnostic-form');
  const targetInput = document.getElementById('target-input');
  const submitBtn = document.getElementById('submit-btn');
  const btnText = document.getElementById('btn-text');
  const btnSpinner = document.getElementById('btn-spinner');
  
  const modeSecuredRadio = document.getElementById('mode-secured');
  const modeVulnerableRadio = document.getElementById('mode-vulnerable');
  const modeSecuredLabel = document.getElementById('mode-secured-label');
  const modeVulnerableLabel = document.getElementById('mode-vulnerable-label');
  const vulnDisabledHint = document.getElementById('vuln-disabled-hint');
  
  const platformBadge = document.getElementById('platform-badge');
  const serverBadge = document.getElementById('server-badge');
  const labBadge = document.getElementById('lab-badge');
  const labWarningBanner = document.getElementById('lab-warning-banner');
  
  const terminalMetadata = document.getElementById('terminal-metadata');
  const metaMode = document.getElementById('meta-mode');
  const metaDuration = document.getElementById('meta-duration');
  const metaExit = document.getElementById('meta-exit');
  
  const commandSpecBox = document.getElementById('command-spec-box');
  const commandSpecText = document.getElementById('command-spec-text');
  const terminalOutput = document.getElementById('terminal-output');
  
  const securityAnalysisBox = document.getElementById('security-analysis-box');
  const analysisIcon = document.getElementById('analysis-icon');
  const analysisTitle = document.getElementById('analysis-title');
  const analysisContent = document.getElementById('analysis-content');
  
  const presetButtons = document.querySelectorAll('.btn-preset');

  // Application State
  let labModeActive = false;
  let serverPlatform = 'unknown';
  let isWindows = true;

  // --------------------------------------------------------------------------
  // 1. Initial Handshake & Lab Mode Detection
  // --------------------------------------------------------------------------
  async function fetchServerStatus() {
    try {
      const response = await fetch('/api/status');
      if (!response.ok) {
        throw new Error(`HTTP error ${response.status}`);
      }
      const data = await response.json();
      
      labModeActive = Boolean(data.labMode);
      serverPlatform = data.platform;
      isWindows = Boolean(data.isWindows);

      // Update badges
      platformBadge.textContent = isWindows ? 'OS: Windows' : `OS: ${serverPlatform}`;
      serverBadge.textContent = `Server: ${data.host}:${data.port}`;

      if (labModeActive) {
        labBadge.textContent = 'Lab Mode: ACTIVE';
        labBadge.className = 'badge badge-status lab-active';
        modeVulnerableRadio.disabled = false;
        modeVulnerableLabel.classList.remove('disabled');
        vulnDisabledHint.classList.add('hidden');
      } else {
        labBadge.textContent = 'Mode: SECURED ONLY';
        labBadge.className = 'badge badge-status lab-inactive';
        modeVulnerableRadio.disabled = true;
        modeVulnerableLabel.classList.add('disabled');
        vulnDisabledHint.classList.remove('hidden');

        // If vulnerable was checked but lab mode is off, switch to secured
        if (modeVulnerableRadio.checked) {
          modeSecuredRadio.checked = true;
        }
      }

      updateModeCardSelection();
    } catch (err) {
      serverBadge.textContent = 'Server: Offline / Error';
      labBadge.textContent = 'Status: Disconnected';
      console.error('Failed to query server status:', err);
    }
  }

  // --------------------------------------------------------------------------
  // 2. Mode Selector UI Sync
  // --------------------------------------------------------------------------
  function updateModeCardSelection() {
    const isVulnerable = modeVulnerableRadio.checked;

    if (isVulnerable) {
      modeSecuredLabel.classList.remove('selected');
      modeVulnerableLabel.classList.add('selected', 'vulnerable');
      
      // Show warning banner when vulnerable mode is selected
      if (labModeActive) {
        labWarningBanner.classList.remove('hidden');
      }
    } else {
      modeSecuredLabel.classList.add('selected');
      modeVulnerableLabel.classList.remove('selected', 'vulnerable');
      labWarningBanner.classList.add('hidden');
    }
  }

  modeSecuredRadio.addEventListener('change', updateModeCardSelection);
  modeVulnerableRadio.addEventListener('change', () => {
    if (!labModeActive) {
      alert('Vulnerable Mode is disabled. To enable it for educational testing, start the server with:\n\nnpm run lab');
      modeSecuredRadio.checked = true;
      updateModeCardSelection();
      return;
    }
    updateModeCardSelection();
  });

  // --------------------------------------------------------------------------
  // 3. Preset Payload Quick-Fill
  // --------------------------------------------------------------------------
  presetButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const payload = btn.getAttribute('data-payload');
      targetInput.value = payload;
      targetInput.focus();
    });
  });

  // --------------------------------------------------------------------------
  // 4. Form Submission & Diagnostic Execution
  // --------------------------------------------------------------------------
  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const target = targetInput.value.trim();
    if (!target) {
      targetInput.focus();
      return;
    }

    const selectedMode = document.querySelector('input[name="executionMode"]:checked').value;
    const isSecured = selectedMode === 'secured';
    const endpoint = isSecured ? '/api/ping/secured' : '/api/ping/vulnerable';

    // Loading State
    setLoadingState(true);
    resetTerminalViewport(selectedMode, target);

    const startTime = performance.now();

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ target: target })
      });

      const clientDurationMs = Math.round(performance.now() - startTime);
      const data = await response.json();

      if (!response.ok) {
        renderErrorResponse(data, response.status, clientDurationMs, selectedMode);
      } else {
        renderSuccessResponse(data, clientDurationMs, selectedMode);
      }
    } catch (networkError) {
      const clientDurationMs = Math.round(performance.now() - startTime);
      renderNetworkError(networkError, clientDurationMs, selectedMode);
    } finally {
      setLoadingState(false);
    }
  });

  // --------------------------------------------------------------------------
  // 5. Safe Output Rendering Functions (Strictly textContent)
  // --------------------------------------------------------------------------
  function setLoadingState(isLoading) {
    submitBtn.disabled = isLoading;
    if (isLoading) {
      btnText.textContent = 'Executing...';
      btnSpinner.classList.remove('hidden');
    } else {
      btnText.textContent = 'Run Diagnostic';
      btnSpinner.classList.add('hidden');
    }
  }

  function resetTerminalViewport(mode, target) {
    metaMode.textContent = mode.toUpperCase();
    metaMode.className = `meta-tag status-${mode}`;
    metaDuration.classList.add('hidden');
    metaExit.classList.add('hidden');

    commandSpecText.textContent = `Dispatching request to server for target: "${target}"...`;
    
    // SAFE: textContent only
    terminalOutput.textContent = `[+] Executing diagnostic on server (${mode} mode)...\n[+] Waiting for process output buffer to flush...\n`;

    securityAnalysisBox.classList.add('hidden');
  }

  function renderSuccessResponse(data, clientDurationMs, mode) {
    const isSecured = mode === 'secured';

    // Update metadata
    metaDuration.textContent = `${data.durationMs || clientDurationMs}ms`;
    metaDuration.classList.remove('hidden');

    metaExit.textContent = `Exit: ${data.exitCode}`;
    metaExit.classList.remove('hidden');

    // Update Command Specification Box (SAFE: textContent)
    if (isSecured) {
      const argsFormatted = JSON.stringify(data.argumentVector || []);
      commandSpecText.textContent = `child_process.execFile("${data.binaryExecuted || 'ping'}", ${argsFormatted}, { shell: false })`;
    } else {
      commandSpecText.textContent = `child_process.exec("${data.commandExecuted || ''}", { shell: true })`;
    }

    // Combine stdout and stderr cleanly
    let terminalBody = '';

    if (data.stdout && data.stdout.trim().length > 0) {
      terminalBody += data.stdout;
    }

    if (data.stderr && data.stderr.trim().length > 0) {
      if (terminalBody.length > 0) {
        terminalBody += '\n--- STDERR STREAM ---\n';
      }
      terminalBody += data.stderr;
    }

    if (terminalBody.trim().length === 0) {
      terminalBody = `[Process finished with exit code ${data.exitCode} and produced no output stream.]`;
    }

    // SAFE RENDERING: MUST use textContent
    terminalOutput.textContent = terminalBody;

    // Render Security Analysis Callout
    renderSecurityAnalysis(data, mode);
  }

  function renderErrorResponse(data, status, durationMs, mode) {
    metaDuration.textContent = `${durationMs}ms`;
    metaDuration.classList.remove('hidden');
    metaExit.textContent = `HTTP ${status}`;
    metaExit.classList.remove('hidden');

    commandSpecText.textContent = `Request failed: HTTP ${status}`;

    // SAFE: textContent
    terminalOutput.textContent = `[!] SERVER REJECTED REQUEST (HTTP ${status})\n\n` +
      `Error   : ${data.error || 'Unknown error'}\n` +
      `Details : ${data.details || 'No additional details provided by server.'}\n`;

    securityAnalysisBox.className = 'security-analysis analysis-vulnerable';
    analysisIcon.textContent = '\u26A0';
    analysisTitle.textContent = 'Access Control Enforced';
    
    // Clear and build safe DOM elements for analysis
    analysisContent.textContent = '';
    const p = document.createElement('p');
    p.textContent = data.details || data.error;
    analysisContent.appendChild(p);
    securityAnalysisBox.classList.remove('hidden');
  }

  function renderNetworkError(error, durationMs, mode) {
    metaDuration.textContent = `${durationMs}ms`;
    metaDuration.classList.remove('hidden');
    metaExit.textContent = 'ERR_CONN';
    metaExit.classList.remove('hidden');

    commandSpecText.textContent = 'Network Connection Error';
    terminalOutput.textContent = `[!] Unable to reach server at 127.0.0.1.\n\nDetails: ${error.message}\nMake sure server.js is running locally.`;

    securityAnalysisBox.classList.add('hidden');
  }

  // --------------------------------------------------------------------------
  // 6. Educational Security Analysis Generator
  // --------------------------------------------------------------------------
  function renderSecurityAnalysis(data, mode) {
    analysisContent.textContent = ''; // clear children safely

    if (mode === 'vulnerable') {
      securityAnalysisBox.className = 'security-analysis analysis-vulnerable';
      analysisIcon.textContent = '\uD83D\uDD25'; // Flame
      analysisTitle.textContent = 'Security Analysis: Vulnerable Command Execution (In-band)';

      const p1 = document.createElement('p');
      p1.innerHTML = '<strong>Mechanism:</strong> The server concatenated the user input directly into a shell command string and passed it to <code>child_process.exec()</code>. The system shell (<code>cmd.exe</code> on Windows or <code>/bin/sh</code> on POSIX) was invoked to parse the string.';
      analysisContent.appendChild(p1);

      const p2 = document.createElement('p');
      p2.style.marginTop = '8px';

      // Check if demonstration payload was likely injected
      const targetLower = (data.targetInput || '').toLowerCase();
      if (targetLower.includes('&') || targetLower.includes(';') || targetLower.includes('|')) {
        p2.innerHTML = '<strong>Exploit Evidence:</strong> The payload contained shell metacharacters. Because the shell parses command separators before running utilities, it executed the chained secondary command (e.g., <code>whoami</code>) in addition to <code>ping</code>. Both outputs were captured in the process output stream and returned to the browser (<strong>In-band OS Command Injection</strong>).';
      } else {
        p2.innerHTML = '<strong>Status:</strong> Legitimate input executed. However, this endpoint remains susceptible to shell metacharacters because input is executed through an unmitigated shell interpreter.';
      }
      analysisContent.appendChild(p2);

    } else {
      securityAnalysisBox.className = 'security-analysis analysis-secured';
      analysisIcon.textContent = '\uD83D\uDEE1\uFE0F'; // Shield
      analysisTitle.textContent = 'Security Analysis: Mitigated via Parameterized Execution';

      const p1 = document.createElement('p');
      p1.innerHTML = '<strong>Mechanism:</strong> The server used <code>child_process.execFile()</code> with an argument vector array and <code>shell: false</code>. The operating system launched the <code>ping</code> executable directly without spawning a shell interpreter.';
      analysisContent.appendChild(p1);

      const p2 = document.createElement('p');
      p2.style.marginTop = '8px';

      const targetLower = (data.targetInput || '').toLowerCase();
      if (targetLower.includes('&') || targetLower.includes(';') || targetLower.includes('|')) {
        p2.innerHTML = '<strong>Defense Verification:</strong> Even though the payload contained shell metacharacters (e.g., <code>& whoami</code>), no command shell was invoked to parse them. The entire payload string was passed as a single literal argument (<code>argv[2]</code>) to the <code>ping</code> executable. The ping utility reported an invalid hostname error and exited. The injected command (<code>whoami</code>) was <strong>never executed</strong>.';
      } else {
        p2.innerHTML = '<strong>Status:</strong> Legitimate input executed safely. User input is strictly isolated as data within the argument vector, never interpreted as instructions.';
      }
      analysisContent.appendChild(p2);
    }

    securityAnalysisBox.classList.remove('hidden');
  }

  // Initial status check
  fetchServerStatus();
});
