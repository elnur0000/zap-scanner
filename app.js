import ZapScanner from './zap-scanner.js'

const targets = ['https://example.com']

process.setMaxListeners(Infinity)

const attack = async (target) => {
  const zapScanner = new ZapScanner(target)

  process.on('SIGINT', async () => {
    console.log(`\n \n received SIGINT, stopping an attack on ${target}...`)
    await zapScanner.stop()
    process.exit(1)
  })

  process.on('SIGTERM', async () => {
    console.log(`\n \n received SIGTERM, stopping an attack on ${target}...`)
    await zapScanner.stop()
    process.exit(1)
  })

  await zapScanner.run()
}

(
  async () => {
    for (const target of targets) {
      try {
        await attack(target)
      } catch (err) {
        console.log(`\n \n Failed to attack target ${target}, reason: ${err.message}`)
      }
    }
    process.exit(0)
  }
)()
