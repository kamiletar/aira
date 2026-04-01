#!/usr/bin/env node
/**
 * Auto-format hook: runs `rustfmt` on .rs files after Write/Edit.
 * Triggered by PostToolUse(Write|Edit).
 */

const { spawnSync } = require('child_process');

const toolInput = process.env.TOOL_INPUT;
if (!toolInput) process.exit(0);

let filePath;
try {
  const parsed = JSON.parse(toolInput);
  filePath = parsed.file_path || parsed.path;
} catch {
  process.exit(0);
}

if (!filePath || !filePath.endsWith('.rs')) {
  process.exit(0);
}

// spawnSync не использует shell — нет command injection
spawnSync('rustfmt', [filePath], { stdio: 'pipe' });
