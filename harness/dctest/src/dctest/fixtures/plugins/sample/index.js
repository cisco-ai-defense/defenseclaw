// dctest fixture: tiny OpenClaw-style plugin entry. No network, no fs,
// no eval. The CodeGuard scanner must produce zero high/critical findings on
// this file or the scanner has regressed.

module.exports = {
  name: 'dctest-sample-plugin',
  hello() {
    return 'ok';
  },
};
