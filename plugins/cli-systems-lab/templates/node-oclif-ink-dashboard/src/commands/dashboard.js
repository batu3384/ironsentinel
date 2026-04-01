import {Command} from '@oclif/core'
import React, {useEffect, useState} from 'react'
import {Box, Text, render, useApp, useInput} from 'ink'

function isInteractive() {
  return process.stdin.isTTY && process.stdout.isTTY && process.env.TERM !== 'dumb' && !process.env.NO_COLOR
}

function PlainDashboard() {
  process.stdout.write('__APP_TITLE__ dashboard\n')
  process.stdout.write('1. Review the active workspace\n')
  process.stdout.write('2. Validate the local toolchain\n')
  process.stdout.write('3. Start the first scan\n')
}

function DashboardApp() {
  const {exit} = useApp()
  const [selected, setSelected] = useState(0)
  const element = React.createElement
  const items = [
    'Review the active workspace',
    'Validate the local toolchain',
    'Start the first scan',
  ]

  useInput((input, key) => {
    if (input === 'q' || key.escape) {
      exit()
      return
    }

    if (input === 'j' || key.downArrow) {
      setSelected(current => Math.min(current + 1, items.length - 1))
    }

    if (input === 'k' || key.upArrow) {
      setSelected(current => Math.max(current - 1, 0))
    }
  })

  useEffect(() => {
    const onResize = () => {}
    process.stdout.on('resize', onResize)
    return () => {
      process.stdout.off('resize', onResize)
    }
  }, [])

  const narrow = process.stdout.columns > 0 && process.stdout.columns < 90

  return element(
    Box,
    {flexDirection: 'column', padding: 1},
    element(Text, {color: 'cyanBright'}, '__APP_TITLE__ operator cockpit'),
    element(Text, {dimColor: true}, 'j/k or arrows move, q exits, plain fallback outside TTY.'),
    element(
      Box,
      {marginTop: 1, flexDirection: 'column'},
      ...items.map((item, index) =>
        element(
          Text,
          {key: item, color: index === selected ? 'magentaBright' : undefined},
          `${index === selected ? '> ' : '  '}${item}`,
        ),
      ),
    ),
    element(
      Box,
      {marginTop: 1},
      element(
        Text,
        {dimColor: true},
        narrow
          ? 'Narrow mode: drop chrome before hiding the main action.'
          : 'Primary action remains visible and machine-safe paths stay plain.',
      ),
    ),
  )
}

export default class DashboardCommand extends Command {
  static description = 'Open the operator dashboard'

  async run() {
    if (!isInteractive()) {
      PlainDashboard()
      return
    }

    const app = render(React.createElement(DashboardApp))
    await app.waitUntilExit()
  }
}
