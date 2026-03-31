const { execFile } = require('child_process')

const MAC_ADDRESS_RE =
  /^([0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2}$/i

function execFileAsync(command, args) {
  return new Promise((resolve, reject) => {
    execFile(command, args, (err, stdout, stderr) => {
      if (err) return reject(err)
      resolve({ stdout, stderr })
    })
  })
}

function normalizeMac(mac) {
  const parts = String(mac || '')
    .trim()
    .replace(/-/g, ':')
    .split(':')

  if (parts.length !== 6 || !parts.every(part => /^[0-9a-f]{1,2}$/i.test(part))) {
    throw new Error(`${mac} is not a valid MAC address`)
  }

  return parts.map(part => part.padStart(2, '0').toLowerCase()).join(':')
}

async function getCurrentMac(device) {
  const { stdout } = await execFileAsync('/sbin/ifconfig', [device])
  const match = stdout.match(/^\s*ether\s+([0-9a-f:]+)/im)
  return match ? normalizeMac(match[1]) : null
}

async function listHardwarePorts() {
  const { stdout } = await execFileAsync('/usr/sbin/networksetup', [
    '-listallhardwareports'
  ])

  const lines = stdout.split('\n')
  const interfaces = []
  let current = null

  for (const line of lines) {
    if (line.startsWith('Hardware Port: ')) {
      if (current) interfaces.push(current)
      current = {
        port: line.slice('Hardware Port: '.length),
        device: null,
        address: null
      }
      continue
    }

    if (!current) continue

    if (line.startsWith('Device: ')) {
      current.device = line.slice('Device: '.length)
      continue
    }

    if (line.startsWith('Ethernet Address: ')) {
      current.address = normalizeMac(line.slice('Ethernet Address: '.length))
    }
  }

  if (current) interfaces.push(current)

  return interfaces.filter(it => it.device)
}

async function findInterface(target) {
  const normalizedTarget = String(target || '').toLowerCase()
  const interfaces = await listHardwarePorts()
  const match = interfaces.find(it => {
    return (
      it.device.toLowerCase() === normalizedTarget ||
      it.port.toLowerCase() === normalizedTarget
    )
  })

  if (!match) {
    throw new Error(`Unable to find network interface: ${target}`)
  }

  return {
    ...match,
    currentAddress: await getCurrentMac(match.device)
  }
}

async function setInterfaceMAC(device, mac) {
  const normalizedMac = normalizeMac(mac)
  await execFileAsync('/sbin/ifconfig', [device, 'ether', normalizedMac])
}

module.exports = {
  findInterface,
  normalizeMac,
  setInterfaceMAC
}
