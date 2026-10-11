// Validation syntaxique du KQL avec la lib officielle Kusto : (@kusto/language-service-next).
'use strict';
const path = require('node:path');
const fs = require('node:fs');

const pkg = path.dirname(require.resolve('@kusto/language-service-next/package.json'));
global.Bridge = require(path.join(pkg, 'bridge.js'));
require(path.join(pkg, 'Kusto.Language.Bridge.js'));
const K = global.Kusto.Language;
const S = K.Symbols;

const TYPE = { string: 'string', int: 'int', long: 'long', real: 'real', bool: 'bool', boolean: 'bool',
  datetime: 'datetime', dynamic: 'dynamic', guid: 'guid', timespan: 'timespan', decimal: 'decimal' };

function loadTables(root) {
  const base = JSON.parse(fs.readFileSync(path.join(root, 'schema/tables.json'), 'utf8'));
  const over = JSON.parse(fs.readFileSync(path.join(root, 'schema/overrides.json'), 'utf8'));
  const tables = JSON.parse(JSON.stringify(base));
  for (const [t, cols] of Object.entries(over.add || {})) tables[t] = Object.assign(tables[t] || {}, cols);
  return { tables, xdrTables: over.xdrTables || [] };
}

function makeGlobals(tables) {
  const syms = [];
  for (const [name, cols] of Object.entries(tables)) {
    const decl = Object.entries(cols)
      .map(([c, t]) => `['${c}']:${TYPE[String(t).toLowerCase()] || 'string'}`)
      .join(', ');
    syms.push(S.TableSymbol.From(`(${decl})`).WithName(name));
  }
  const db = new S.DatabaseSymbol.$ctor2('workspace', null, syms);
  return K.GlobalState.Default.WithDatabase(db);
}

function lineCol(text, offset) {
  const before = text.slice(0, offset).split('\n');
  return { line: before.length, col: before[before.length - 1].length + 1 };
}

function createValidator(root) {
  const { tables, xdrTables } = loadTables(root);
  const globals = makeGlobals(tables);
  return {
    tables,
    xdrTables,
    validate(query) {
      const code = K.KustoCode.ParseAndAnalyze(query, globals);
      const diags = code.GetDiagnostics();
      const out = [];
      for (let i = 0; i < diags.Count; i++) {
        const d = diags.getItem(i);
        const { line, col } = lineCol(query, d.Start);
        out.push({ severity: String(d.Severity), code: d.Code, message: d.Message, line, col,
          snippet: query.split('\n')[line - 1] });
      }
      return out;
    },
  };
}

module.exports = { createValidator };
