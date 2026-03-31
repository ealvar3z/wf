const spawn = require('child_process').spawn

const darwinPing = (ip) => {
  return new Promise((resolve, _) => {
    const process = spawn('ping', ['-c', '1', ip])
    process.on('close', (code) => {
      resolve()
    })
  })
}


module.exports = (ip) => {
  if (process.platform !== 'darwin') {
    throw new Error('wf currently supports macOS only.')
  }

  return darwinPing(ip)
}
