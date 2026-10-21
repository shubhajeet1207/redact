// Runtime UI text (TRD §10.1), kept in one place for localization. Static page copy lives in
// index.html. No message ever says the output is "safe" and none shows a risk score (§10.2).

export const S = {
  status: {
    initializing: 'Starting the local engine…',
    empty: 'Paste or type text to sanitize it. Nothing leaves this device.',
    pending: 'Sanitizing…',
    none: 'No matches found — review before sharing',
    some: (n: number) => `${n} replacement${n === 1 ? '' : 's'} — review before sharing`,
    unavailable:
      'The local engine stopped responding. Reload the page, or use the command-line tool for large inputs.',
    timeout: 'Sanitizing took too long and was stopped. Edit the text to try again.',
    rulesMismatch: 'The engine’s rule set does not match this page. Reload the page.',
  },
  hidden: (n: number) =>
    `${n} hidden or control character${n === 1 ? '' : 's'} in the output — shown as badges such as ⟨U+202E⟩.`,
  highlightLimited: (cap: number) =>
    `More than ${cap.toLocaleString('en')} placeholders or hidden characters: showing plain text without highlighting. Redaction is still complete.`,
  copy: {
    label: 'Copy output',
    done: 'Copied sanitized output',
    failed: 'Copy failed. Select the output and copy it manually.',
    stale: 'The text changed before copying finished; copy again.',
  },
  confirmSample: 'Replace your edited input with the sample?',
  errors: {
    INVALID_UTF8: 'The input is not valid UTF-8.',
    INVALID_UTF16: 'The file is not valid UTF-16.',
    UTF16_WITHOUT_BOM: 'The file looks like UTF-16 without a byte-order mark. Save it as UTF-8, or use the CLI with --input-encoding.',
    UNSUPPORTED_ENCODING: 'UTF-32 files are not supported.',
    NUL_BYTE: 'The input contains a NUL character; binary files are not supported.',
    LINE_TOO_LONG: 'A line is longer than the maximum line length. Raise the limit and try again.',
    INPUT_TOO_LARGE: 'Paste mode accepts up to 1 MiB. Use file mode for larger inputs.',
    INVALID_OPTIONS: 'The engine rejected these options.',
    INTERNAL_ERROR: 'Internal error. No output was produced for this input.',
    OUTPUT_TOO_LARGE: 'The output exceeds 1 GiB in memory. Choose “Stream to disk” instead.',
    WRITE_FAILED: 'Writing the output file failed; the partial file was discarded.',
    READ_FAILED: 'Reading the file failed.',
    CANCELLED: 'Cancelled. No output was saved.',
    ENGINE_UNAVAILABLE: 'The local engine is unavailable. Reload the page.',
  } as Record<string, string>,
  errorAtLine: (message: string, line: number) => `${message} (line ${line.toLocaleString('en')})`,
  file: {
    idle: 'Choose a file. It is read and sanitized on this device; nothing is uploaded.',
    progress: (done: string, total: string) => `Sanitizing… ${done} of ${total}`,
    done: (n: number) => `Done: ${n} replacement${n === 1 ? '' : 's'} — review before sharing`,
    savedToDisk: 'The sanitized file was saved where you chose.',
    saveLabel: 'Save sanitized file',
    downloadNote: 'Your browser records the file name in its download history.',
    pickerCancelled: 'No destination was chosen, so nothing was started.',
    timeout: 'The file job stopped responding and was stopped. Try again.',
    previewNote: (shown: string) => `Preview of the first ${shown} of the sanitized output.`,
    copyTooLarge: 'Copy is available when the output is 1 MiB or less.',
  },
  warnings: {
    UNTERMINATED_PRIVATE_KEY_BLOCK: (line: number) =>
      `A private-key block starting on line ${line.toLocaleString('en')} never ended; everything after it was removed.`,
    UNSTABLE_LINE_REDACTED: (line: number, lines: number) =>
      `${lines.toLocaleString('en')} line${lines === 1 ? '' : 's'} (first: ${line.toLocaleString('en')}) kept producing new matches and ${lines === 1 ? 'was' : 'were'} replaced entirely.`,
  },
  options: (email: boolean, ip: boolean) =>
    `Emails ${email ? 'on' : 'off'} · Private IPs ${ip ? 'on' : 'off'}`,
} as const;

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let value = n / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit] ?? 'TiB'}`;
}

export function errorText(code: string, line?: number): string {
  const message = S.errors[code] ?? S.errors['INTERNAL_ERROR'] ?? code;
  return line === undefined ? message : S.errorAtLine(message, line);
}
