const os = require('os')
const { isIP } = require('net')
const { execFile } = require('child_process')

const DEFAULT_DESTINATIONS = new Set([
  'default',
  '0.0.0.0',
  '0.0.0.0/0',
  '::',
  '::/0'
])

const V4_ARGS = ['-rn', '-f', 'inet']
const V6_ARGS = ['-rn', '-f', 'inet6']
const V4_IFACE_COLUMN = parseInt(os.release(), 10) >= 19 ? 3 : 5

function execFileAsync(command, args) {
  return new Promise((resolve, reject) => {
    execFile(command, args, (err, stdout, stderr) => {
      if (err) return reject(err)
      resolve({ stdout, stderr })
    })
  })
}

function parseGateway(stdout, family) {
  const ifaceColumn = family === 'v4' ? V4_IFACE_COLUMN : 3
  const lines = String(stdout || '').trim().split('\n')

  for (const line of lines) {
    const columns = line.trim().split(/ +/)
    const target = columns[0]
    const gateway = columns[1]
    const iface = columns[ifaceColumn]

    if (DEFAULT_DESTINATIONS.has(target) && gateway && isIP(gateway)) {
      return {
        gateway,
        interface: iface || null
      }
    }
  }

  throw new Error('Unable to determine default gateway')
}

async function lookup(family) {
  if (process.platform !== 'darwin') {
    throw new Error('wf currently supports macOS only.')
  }

  const args = family === 'v6' ? V6_ARGS : V4_ARGS
  const { stdout } = await execFileAsync('/usr/sbin/netstat', args)
  return parseGateway(stdout, family)
}

module.exports = {
  v4: () => lookup('v4'),
  v6: () => lookup('v6')
}
