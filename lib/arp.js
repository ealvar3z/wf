const spawn = require('child_process').spawn

const spawnArp = () => {
  const process = spawn('arp', ['-a'])
  let buffer = ''
  process.stdout.on('data', (data) => {
    buffer += data
  })

  return new Promise((resolve, reject) => {
    process.on('close', (code) => {
      if (code !== 0) {
        reject(new Error('arp exited with code ' + code))
      }
      resolve(buffer)
    })
  })
}

const listDarwinMACs = async (gatewayIP) => {
  const buffer = await spawnArp()
  const lines = buffer.split('\n').slice(0, -1)
  const macs = lines
    .map(line => {
      const parts = line.split(' ')
      if (parts[1].slice(1, -1) == gatewayIP) return null

      return parts[3]
        .replace(/^0:/g, '00:')
        .replace(/:0:/g, ':00:')
        .replace(/:0$/g, ':00')
        .replace(/:([^:]{1}):/g, ':0$1:')
    })
    .filter(mac => mac && mac !== '(incomplete)')
  return macs
}

module.exports.listMACs = (gatewayIP) => {
  if (process.platform !== 'darwin') {
    throw new Error('wf currently supports macOS only.')
  }

  return listDarwinMACs(gatewayIP)
}
