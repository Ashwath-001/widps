// CSV export with spreadsheet-formula neutralisation: SSIDs and alert text come from untrusted radio frames.
const FORMULA_START = /^[=+\-@\t\r]/;

/** Numbers are written as-is (negative RSSI stays numeric); text starting with = + - @ tab or CR gets a leading quote. */
export function csvCell(value: unknown): string {
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  let s = value === null || value === undefined ? '' : String(value);
  if (FORMULA_START.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

export function toCsv(headers: string[], rows: unknown[][]): string {
  return [headers.map(csvCell).join(','), ...rows.map((r) => r.map(csvCell).join(','))].join('\r\n');
}

export function downloadCsv(filename: string, headers: string[], rows: unknown[][]) {
  const blob = new Blob(['\ufeff' + toCsv(headers, rows)], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
