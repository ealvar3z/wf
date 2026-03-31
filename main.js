#!/usr/bin/env node

const HELP_TEXT = `
wf CLI

Usage:
  sudo wf bypass [--silent]
  sudo wf scan
  sudo wf reset
  wf list
  wf status
  wf help

Commands:
  bypass   Attempt captive portal bypass by cycling through
           discovered MAC addresses.
  scan     Ping the local subnet to populate the ARP table before
           listing clients.
  reset    Restore the interface MAC address to its hardware value.
  list     Print candidate client MAC addresses seen on the current network.
  status   Print whether you are on an open Wi-Fi network and whether
           internet access works.
  help     Show this help text.

Options:
  --silent Skip the active subnet scan and only try
           already-discovered MAC addresses.
`.trim()

function fail(message, code = 1) {
  console.error(message)
  process.exit(code)
}

function requireRoot() {
  const isRoot = process.getuid && process.getuid() === 0
  if (!isRoot) {
    fail('This command must run as root on macOS. Re-run it with sudo.')
  }
}

async function printStatus() {
  const wf = require('./lib/wf')
  const onOpenNetwork = await wf.isOnOpenNetwork()
  const hasInternetAccess = await wf.hasInternetAccess()

  console.log(`Open Wi-Fi network: ${onOpenNetwork ? 'yes' : 'no'}`)
  console.log(`Internet access: ${hasInternetAccess ? 'yes' : 'no'}`)
}

async function printValidMacs() {
  const wf = require('./lib/wf')
  const macs = await wf.listValidMacs()
  if (macs.length === 0) {
    console.log('No candidate client MAC addresses found.')
    return
  }

  macs.forEach((mac) => {
    console.log(mac)
  })
}

async function run() {
  const args = process.argv.slice(2)
  const command = args[0] || 'help'
  const silentMode = args.includes('--silent')

  switch (command) {
    case 'bypass':
    {
      const wf = require('./lib/wf')
      requireRoot()
      console.log(`Starting bypass${silentMode ? ' in silent mode' : ''}...`)
      await wf.connect(silentMode)
      console.log('Bypass complete.')
      return
    }

    case 'scan':
    {
      const wf = require('./lib/wf')
      requireRoot()
      console.log('Scanning local subnet...')
      await wf.manualScan()
      console.log('Scan complete.')
      return
    }

    case 'reset':
    {
      const wf = require('./lib/wf')
      requireRoot()
      await wf.reset()
      console.log('Restored the hardware MAC address.')
      return
    }

    case 'list':
      await printValidMacs()
      return

    case 'status':
      await printStatus()
      return

    case 'help':
    case '--help':
    case '-h':
      console.log(HELP_TEXT)
      return

    default:
      fail(`Unknown command: ${command}\n\n${HELP_TEXT}`)
  }
}

run().catch((err) => {
  fail(err && err.message ? err.message : String(err))
})
