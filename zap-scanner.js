import cliProgress from 'cli-progress'
import ZapClient from 'zaproxy'
import fs from 'fs/promises'
import path from 'path'
import { setTimeout } from 'timers/promises'

const zaproxy = new ZapClient({
  apiKey: '< Your ZAP Api key>',
  proxy: '< ZAP host address >'
})

const riskIds = {
  high: 3,
  medium: 2,
  low: 1
}

const waitFor = async (checkIsConditionSatisfied, delay = 300, maxWait) => {
  while (!(await checkIsConditionSatisfied())) {
    await setTimeout(delay)
  }

  return Promise.resolve()
}

const Bar = new cliProgress.MultiBar({ format: '{bar} | {title} | {value}/{total}', autopadding: true }, cliProgress.Presets.shades_classic)

class Marauder {
  constructor (target, riskId = riskIds.high, activeScan = true) {
    this.contextName = target.slice(target.indexOf('//') + 2)
    this.target = target
    this.folderName = path.join('scans', this.contextName)
    this.spiderResultPath = path.join(this.folderName, 'spider-results.json')
    this.scanAlertsPath = path.join(this.folderName, 'scan-alerts.json')
    this.riskId = riskId
    this.activeScan = activeScan
  }

  async run () {
    await Promise.all(
      [
        this._createTargetFolder(),
        this._excludeScannedPaths(),
        this._createContext()
      ]
    )
    await this._spider()
    await Promise.all(
      [
        this._pscan(),
        this.activeScan && this._ascan()
      ]
    )
    await Promise.all(
      [
        this._saveAlerts(),
        this._saveSpideringResults()
      ]
    )
  }

  async _excludeScannedPaths () {
    let fileExists = true
    try {
      await fs.access(this.spiderResultPath)
    } catch (e) {
      fileExists = false
    }

    if (!fileExists) return

    const scanAlerts = (await fs.readFile(this.spiderResultPath)).toString()
    const parsedScanAlerts = JSON.parse(scanAlerts)
    for (const url of parsedScanAlerts.results) {
      await zaproxy.ascan.excludeFromScan(url)
    }
  }

  async _createContext () {
    const contexts = await zaproxy.context.contextList()
    if (contexts.contextList.includes(this.contextName)) {
      await zaproxy.context.removeContext(this.contextName)
    }
    await zaproxy.context.newContext(this.contextName)
    await zaproxy.context.includeInContext(this.contextName, `${this.target}.*`)
  }

  async _spider () {
    this.spiderScanId = await zaproxy.spider.scan(this.target, undefined, undefined, this.contextName)
    const bar = Bar.create(100, 0, { title: `Spidering ${this.target}` })
    await waitFor(async () => {
      const scanStatus = await zaproxy.spider.status(this.spiderScanId)
      bar.update(parseInt(scanStatus.status))
      return scanStatus.status === '100'
    })
  }

  async _pscan () {
    const result = await zaproxy.pscan.recordsToScan()
    const total = parseInt(result.recordsToScan)
    const bar = Bar.create(total, 0, { title: `Passive scan ${this.target}` })
    await waitFor(async () => {
      const pscanStatus = await zaproxy.pscan.recordsToScan()
      bar.update(total - parseInt(pscanStatus.recordsToScan))
      return pscanStatus.recordsToScan === '0'
    })
  }

  async _ascan () {
    const context = await zaproxy.context.context(this.contextName)
    this.ascanId = await zaproxy.ascan.scan(this.target, undefined, true, undefined, undefined, undefined, context.context.id)
    const bar = Bar.create(100, 0, { title: `Active scan ${this.target}` })
    await waitFor(async () => {
      const scanStatus = await zaproxy.ascan.status(this.ascanId)
      bar.update(parseInt(scanStatus.status))
      return scanStatus.status === '100'
    })
  }

  async _createTargetFolder () {
    let folderExists = true
    try {
      await fs.access(this.folderName)
    } catch (e) {
      folderExists = false
    }
    if (!folderExists) {
      await fs.mkdir(this.folderName)
    }
  }

  async _saveSpideringResults () {
    console.log(`\n \n Writing spider results to ${this.spiderResultPath}...`)
    const results = await zaproxy.spider.results(this.spiderScanId)
    await fs.writeFile(this.spiderResultPath, JSON.stringify(results))
  }

  async _saveAlerts () {
    console.log(`\n \n Writing scan alerts to ${this.scanAlertsPath}...`)
    const scanResult = await zaproxy.core.alerts(this.target, undefined, undefined, this.riskId)
    await fs.writeFile(this.scanAlertsPath, JSON.stringify(scanResult))
  }

  async stop () {
    await Promise.all(
      [
        this._saveAlerts(),
        this._saveSpideringResults()
      ]
    )
    await Promise.all([
      this.ascanId && zaproxy.ascan.stop(this.ascanId.scan),
      this.spiderScanId && zaproxy.spider.stop(this.spiderScanId)
    ])
  }
}

export default Marauder
