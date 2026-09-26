/* Shared derivations that turn page data into KnowledgeMap props.
 *
 * The category taxonomy mirrors the backend (app/reporting/mappings.py
 * CATEGORY_ORDER / CATEGORY_LABELS) so the map, the reports and the API all
 * name the same families. Quality is a severity roll-up: high = critical+high,
 * medium = medium, low = low+info - the "how bad is what we found here" split
 * the knowledge map's quality ring expects.
 */
export const CATEGORY_LABELS = {
  recon: 'Reconnaissance',
  enumeration: 'Mapping & enumeration',
  access_control: 'Access control',
  injection: 'Injection & exploitation',
  auth_secrets: 'Auth & secrets',
  config: 'Server & config',
  other: 'Other',
};
export const CATEGORY_ICONS = {
  recon: 'RE', enumeration: 'EN', access_control: 'AC',
  injection: 'IN', auth_secrets: 'AS', config: 'CF', other: 'OT',
};
const ORDER = ['injection', 'access_control', 'auth_secrets', 'config', 'enumeration', 'recon', 'other'];

export function qualityForSeverity(severity) {
  const s = (severity || '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'high';
  if (s === 'medium') return 'med';
  return 'low';
}

// Group findings by their `category`, count severity into high/med/low, and
// compute confidence as the share confirmed. `confirmed(f)` decides what counts
// as confirmed (validation status differs between the two finding shapes).
export function mapFromFindings(findings, { confirmed } = {}) {
  const isConfirmed = confirmed || ((f) => (f.validation_status || f.status) === 'confirmed');
  const buckets = {};
  let confirmedN = 0;
  for (const f of findings) {
    const cat = f.category || 'other';
    const b = buckets[cat] || (buckets[cat] = { key: cat, label: CATEGORY_LABELS[cat] || cat, icon: CATEGORY_ICONS[cat] || 'OT', count: 0, high: 0, med: 0, low: 0 });
    b.count += 1;
    b[qualityForSeverity(f.severity)] += 1;
    if (isConfirmed(f)) confirmedN += 1;
  }
  const categories = Object.values(buckets)
    .sort((a, b) => (ORDER.indexOf(a.key) - ORDER.indexOf(b.key)) || (b.count - a.count));
  const confidence = findings.length ? Math.round((confirmedN / findings.length) * 100) : 0;
  return { categories, confidence };
}
