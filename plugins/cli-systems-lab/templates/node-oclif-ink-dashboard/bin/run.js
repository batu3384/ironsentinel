#!/usr/bin/env node
import {fileURLToPath} from 'node:url'
import {execute} from '@oclif/core'

const rootDir = fileURLToPath(new URL('..', import.meta.url))

await execute({dir: rootDir})
