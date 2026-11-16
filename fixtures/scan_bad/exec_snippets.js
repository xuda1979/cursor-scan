// Deliberately unsafe dynamic code execution via Node's vm module.
const vm = require("node:vm");

function evaluateExpression(expr) {
  return vm.runInThisContext(expr);
}

function sandboxUserModule(source) {
  return vm.runInNewContext(source);
}

function evaluateInContext(code, context) {
  return vm.runInContext(code, context);
}

function applyPatch(diffText) {
  const harness = require("vm");
  return harness.runInThisContext(diffText);
}
