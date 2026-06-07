

const order = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

export function riskGte(actual, expected) {
  if (!actual) return false;
  return order[actual] >= order[expected];
}

export function maxRisk(levels) {
  let best;
  for (const level of levels) {
    if (!level) continue;
    if (!best || order[level] > order[best]) best = level;
  }
  return best;
}

export function compareRisk(a, b) {
  return order[a] - order[b];
}

//# sourceMappingURL=risk.js.map
