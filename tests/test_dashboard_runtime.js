const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const {join} = require('node:path');
const {test} = require('node:test');
const vm = require('node:vm');

class Element {
  constructor() {
    this.children = [];
    this.style = {};
    this.classList = {toggle() {}, add() {}, remove() {}};
    this.parts = new Map();
  }
  replaceChildren(...children) { this.children = children; }
  append(...children) { this.children.push(...children); }
  appendChild(child) { this.append(child); }
  setAttribute() {}
  querySelector(selector) {
    if (!this.parts.has(selector)) this.parts.set(selector, new Element());
    return this.parts.get(selector);
  }
}

function dashboard() {
  const elements = new Map();
  const document = {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, new Element());
      return elements.get(id);
    },
    createElement: () => new Element(),
    createTextNode: text => ({textContent: text})
  };
  const html = readFileSync(join(__dirname, '..', 'frontend', 'dashboard.html'), 'utf8');
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  const context = vm.createContext({document});
  vm.runInContext(script.slice(0, script.lastIndexOf('    loadOtaCatalog();')), context);
  return {context, document};
}

function scan(attackType, category, count) {
  return {
    scan_id: attackType,
    attack_type: attackType,
    scan_status: 'completed',
    risk_level: 'high',
    attack_summary: {status: 'completed'},
    target_summary: {target_node_ids: ['ecu-powertrain']},
    before_attack: {
      security_event_count: 500,
      security_event_categories: {[category]: 500}
    },
    after_attack: {
      security_event_count: 500,
      security_event_categories: {[category]: 500},
      new_security_event_count: count,
      new_security_event_categories: {[category]: count},
      ota_weakness_findings: [{
        weakness_id: 'W1', title: 'Replay protection disabled',
        affected_target_count: 1
      }]
    }
  };
}

test('consecutive scans replace outcomes and chart even with unchanged OTA posture', () => {
  const {context, document} = dashboard();
  for (const [attack, category, count] of [
    ['replay_attack', 'replay_detected', 20],
    ['spoofing', 'invalid_authentication', 30],
    ['spoofing', 'invalid_authentication', 40]
  ]) {
    context.renderAnalytics(scan(attack, category, count));
    const legend = document.getElementById('post-attack-legend').children
      .map(item => item.children.map(child => child.textContent || '').join('')).join(' ');
    assert.match(legend, new RegExp(`${count} `));
    assert.match(legend, /W1/);
    assert.equal(
      document.getElementById('outcome-risk').querySelector('strong').textContent,
      'High'
    );
    assert.match(
      document.getElementById('outcome-decision').querySelector('p').textContent,
      new RegExp(attack.replaceAll('_', ' '))
    );
  }
  context.renderAnalytics(null);
  assert.equal(
    document.getElementById('outcome-decision').querySelector('strong').textContent,
    'Awaiting assessment'
  );
  assert.equal(document.getElementById('post-attack-legend').children.length, 0);
});

test('legacy reports retain count-delta behavior', () => {
  const {context} = dashboard();
  const counts = context.newSecurityEventCounts(
    {security_event_categories: {replay_detected: 2}, security_event_count: 2},
    {security_event_categories: {replay_detected: 5}, security_event_count: 5}
  );
  assert.equal(counts.replay_detected, 3);
});

test('bounded flooding is allowed in every mode without removing other safe-mode limits', () => {
  const {context} = dashboard();
  for (const mode of ['service_center_safe', 'oem_validation', 'lab_penetration_test']) {
    assert.equal(context.scanPolicyMessage('flooding', 'medium', mode), '');
  }
  assert.match(context.scanPolicyMessage('flooding', 'high', 'service_center_safe'), /not allowed/);
  assert.match(context.scanPolicyMessage('dos', 'medium', 'service_center_safe'), /blocked/);
});
