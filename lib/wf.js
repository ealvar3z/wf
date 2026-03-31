const defaultGateway = require('default-gateway')
const os = require('os')
const { execFile } = require('child_process')
const macSpoof = require('./mac-spoof')
const ping = require('./ping')
const arp = require('./arp')
const cidrRange = require('./cidr-range')

const BLOCK_SIZE = 255
const SUCCESS_URL = 'http://www.apple.com/library/test/success.html'
const SUCCESS_BODY =
  '<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>'

const checkIsConnected = async () => {
  try {
    const response = await fetch(SUCCESS_URL)
    const body = await response.text()
    return body === SUCCESS_BODY
  } catch (err) {
    return false
  }
}

module.exports.hasInternetAccess = checkIsConnected

function execFileAsync(command, args) {
  return new Promise((resolve, reject) => {
    execFile(command, args, (err, stdout, stderr) => {
      if (err) return reject(err)
      resolve({ stdout, stderr })
    })
  })
}

async function reconnectToOpenNetwork(iface, ssid) {
  await execFileAsync('/usr/sbin/networksetup', [
    '-setairportnetwork',
    iface,
    ssid
  ])
}

async function getCurrentConnection() {
  if (process.platform !== 'darwin') {
    throw new Error('wf currently supports macOS only.')
  }

  const { stdout } = await execFileAsync('/usr/sbin/system_profiler', [
    'SPAirPortDataType',
    '-json'
  ])
  const payload = JSON.parse(stdout)
  const airportData = payload.SPAirPortDataType || []
  const interfaces = airportData.flatMap(
    item => item.spairport_airport_interfaces || []
  )
  const connectedInterface = interfaces.find(
    item => item.spairport_status_information === 'spairport_status_connected'
  )

  if (!connectedInterface) {
    return null
  }

  const current = connectedInterface.spairport_current_network_information || {}
  return {
    iface: connectedInterface._name,
    ssid: current._name,
    security: current.spairport_security_mode || 'unknown'
  }
}

function normalizeSecurityMode(securityMode) {
  return String(securityMode || '')
    .toLowerCase()
    .replace(/^spairport_security_mode_/, '')
}

module.exports.isOnOpenNetwork = async () => {
  const currentConnection = await getCurrentConnection()
  if (!currentConnection) {
    return false
  }
  if (normalizeSecurityMode(currentConnection.security) !== 'none') {
    return false
  }
  return true
}

function isMulticastAddress(mac) {
  // 1 in the LSB of the first octet indicates a multicast address.
  return parseInt(mac.split(':')[0], 16) & 1
}

function isBroadcastAddress(mac) {
  return mac === 'FF:FF:FF:FF:FF:FF'
}

async function getRouteContext() {
  const { gateway, interface } = await defaultGateway.v4() // TODO: v6 support
  return { gateway, interface }
}

function getInterfaceAddress(interfaceName) {
  return os.networkInterfaces()[interfaceName]
    .filter(i => i.family === 'IPv4')[0]
}

module.exports.listValidMacs = async (routeContext) => {
  const context = routeContext || await getRouteContext()
  const iface = getInterfaceAddress(context.interface)
  return (await arp.listMACs(context.gateway))
    .filter(mac => mac !== iface.mac)
    .filter(mac => !isMulticastAddress(mac))
    .filter(mac => !isBroadcastAddress(mac))
}

async function pingScan(interface, blockCallback) {
  // get interface object
  const iface = getInterfaceAddress(interface)

  // get all IPs in CIDR range of gateway
  const range = cidrRange(iface.cidr, { onlyHosts: true })

  // ping scan a block of IPs
  let i = 0
  while (i < range.length) {
    const isConnected = await blockCallback()
    if (isConnected) return true

    const block = range.slice(i, i + BLOCK_SIZE)
    console.log('Scanning next block of', BLOCK_SIZE)
    await Promise.all(block.map((ip) => {
      return ping(ip)
    }))
    i += BLOCK_SIZE
  }

  console.log('Scan complete.')
  return false
}

module.exports.manualScan = async () => {
  const routeContext = await getRouteContext()
  await pingScan(routeContext.interface, async () => { return false })
}

async function tryMACs(attemptedMACs, initialSSID, it, routeContext) {
  const newMACs = (await module.exports.listValidMacs(routeContext))
    .filter(mac => attemptedMACs.indexOf(mac) === -1)
  for (let j = 0; j < newMACs.length; ++j) {

    // spoof MAC
    console.log('Trying MAC', newMACs[j])
    await macSpoof.setInterfaceMAC(it.device, newMACs[j])
    attemptedMACs.push(newMACs[j])

    // Force a reconnect using supported macOS tooling.
    await reconnectToOpenNetwork(it.device, initialSSID)

    if (await checkIsConnected()) {
      console.log('Connected with MAC', newMACs[j])
      return true
    }
  }
  console.log('Done trying block of MACs')
  return false
}

module.exports.connect = async (silentMode) => {
  if (await checkIsConnected()) return // try our initial MAC

  // get default gateway, interface name
  const routeContext = await getRouteContext()
  const it = await macSpoof.findInterface(routeContext.interface)

  const currentConnection = await getCurrentConnection()
  if (!currentConnection) {
    console.log('Not connected to any network')
    throw new Error('Not connected to any network.')
  }
  console.log('Network security', currentConnection.security)
  if (normalizeSecurityMode(currentConnection.security) !== 'none') {
    console.log(currentConnection.ssid, 'is not an open network.')
    throw new Error('wf only works with open networks.')
  }
  const initialSSID = currentConnection.ssid
  const iface = getInterfaceAddress(routeContext.interface)
  const attemptedMACs = [iface.mac]

  let isConnected = false
  if (silentMode) {
    isConnected = await tryMACs(
      attemptedMACs,
      initialSSID,
      it,
      routeContext
    )
  } else {
    isConnected = await pingScan(routeContext.interface, async () => {
      return await tryMACs(
        attemptedMACs,
        initialSSID,
        it,
        routeContext
      )
    })
  }
  if (isConnected) return

  console.log('Failed to connect with any MAC')
  if (attemptedMACs.length > 1) {
    throw new Error("wf couldn't bypass the captive portal.")
  } else {
    throw new Error('No other users are on this network.')
  }
}

module.exports.reset = async () => {
  // get default gateway, interface name
  const { interface } = await defaultGateway.v4() // TODO: v6 support
  const it = await macSpoof.findInterface(interface)

  await macSpoof.setInterfaceMAC(it.device, it.address)
}
