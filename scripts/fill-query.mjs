export function fillQuery(rule, { value, t0, beforeMinutes, afterMinutes, host } = {}, variant = 'query') {
  const verbatim = (s) => String(s ?? '').replace(/"/g, '""');
  const iso = t0 instanceof Date ? t0.toISOString() : (t0 ? new Date(t0).toISOString() : '');
  const int = (n) => (Number.isFinite(Number(n)) && n !== '' && n != null ? String(Math.trunc(Number(n))) : '');
  const values = {
    VALUE: verbatim(value),
    T0: iso,
    BEFORE_MIN: int(beforeMinutes),
    AFTER_MIN: int(afterMinutes),
    HOST: verbatim(host),
  };
  return (rule[variant] || rule.query).replace(/\{\{(VALUE|T0|BEFORE_MIN|AFTER_MIN|HOST)\}\}/g, (_, k) => values[k]);
}
export function matchesIndicator(indicator, value) {
  return indicator.patterns.some((p) => {
    const ci = p.startsWith('(?i)');
    return new RegExp(ci ? p.slice(4) : p, ci ? 'i' : '').test(String(value).trim());
  });
}
