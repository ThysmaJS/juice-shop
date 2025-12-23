import fs from 'node:fs'
import path from 'node:path'
import yaml from 'js-yaml'
import { type NextFunction, type Request, type Response } from 'express'

import * as accuracy from '../lib/accuracy'
import * as challengeUtils from '../lib/challengeUtils'
import { type ChallengeKey } from 'models/challenge'

const FixesDir = 'data/static/codefixes'

interface codeFix {
  fixes: string[]
  correct: number
}

type cache = Record<string, codeFix>

const CodeFixes: cache = {}

export const readFixes = (key: string) => {
  // Security fix: Validate key parameter to prevent path traversal
  if (!key || typeof key !== 'string') {
    return { fixes: [], correct: -1 }
  }
  
  // Security fix: Allow only alphanumeric characters, hyphens and underscores
  if (!/^[a-zA-Z0-9_-]+$/.test(key)) {
    return { fixes: [], correct: -1 }
  }
  
  if (CodeFixes[key]) {
    return CodeFixes[key]
  }
  const files = fs.readdirSync(FixesDir)
  const fixes: string[] = []
  let correct: number = -1
  
  for (const file of files) {
    if (file.startsWith(`${key}_`)) {
      // Security fix: Use path.join to safely construct file paths
      const safeFilePath = path.join(FixesDir, file)
      
      // Security fix: Ensure the resolved path is still within the expected directory
      const resolvedPath = path.resolve(safeFilePath)
      const expectedDir = path.resolve(FixesDir)
      
      if (resolvedPath.startsWith(expectedDir)) {
        const fix = fs.readFileSync(safeFilePath).toString()
        const metadata = file.split('_')
        const number = metadata[1]
        fixes.push(fix)
        if (metadata.length === 3) {
          correct = parseInt(number, 10)
          correct--
        }
      }
    }
  }

  CodeFixes[key] = {
    fixes,
    correct
  }
  return CodeFixes[key]
}

interface FixesRequestParams {
  key: string
}

interface VerdictRequestBody {
  key: ChallengeKey
  selectedFix: number
}

export const serveCodeFixes = () => (req: Request<FixesRequestParams, Record<string, unknown>, Record<string, unknown>>, res: Response, next: NextFunction) => {
  const key = req.params.key
  
  // Security fix: Validate key parameter to prevent path traversal
  if (!key || typeof key !== 'string') {
    return res.status(400).json({ error: 'Invalid key parameter' })
  }
  
  // Security fix: Allow only alphanumeric characters, hyphens and underscores
  if (!/^[a-zA-Z0-9_-]+$/.test(key)) {
    return res.status(400).json({ error: 'Invalid key format' })
  }
  
  const fixData = readFixes(key)
  if (fixData.fixes.length === 0) {
    res.status(404).json({
      error: 'No fixes found for the snippet!'
    })
    return
  }
  res.status(200).json({
    fixes: fixData.fixes
  })
}

export const checkCorrectFix = () => async (req: Request<Record<string, unknown>, Record<string, unknown>, VerdictRequestBody>, res: Response, next: NextFunction) => {
  const key = req.body.key
  const selectedFix = req.body.selectedFix
  
  // Security fix: Validate key parameter to prevent path traversal
  if (!key || typeof key !== 'string') {
    return res.status(400).json({ error: 'Invalid key parameter' })
  }
  
  // Security fix: Allow only alphanumeric characters, hyphens and underscores
  if (!/^[a-zA-Z0-9_-]+$/.test(key)) {
    return res.status(400).json({ error: 'Invalid key format' })
  }
  
  const fixData = readFixes(key)
  if (fixData.fixes.length === 0) {
    res.status(404).json({
      error: 'No fixes found for the snippet!'
    })
  } else {
    let explanation
    // Security fix: Use path.join and validate the file path
    const safeFilePath = path.join('./data/static/codefixes/', key + '.info.yml')
    
    // Security fix: Ensure the resolved path is still within the expected directory
    const resolvedPath = path.resolve(safeFilePath)
    const expectedDir = path.resolve('./data/static/codefixes/')
    
    if (resolvedPath.startsWith(expectedDir) && fs.existsSync(safeFilePath)) {
      const codingChallengeInfos = yaml.load(fs.readFileSync(safeFilePath, 'utf8'))
      const selectedFixInfo = codingChallengeInfos?.fixes.find(({ id }: { id: number }) => id === selectedFix + 1)
      if (selectedFixInfo?.explanation) explanation = res.__(selectedFixInfo.explanation)
    }
    if (selectedFix === fixData.correct) {
      await challengeUtils.solveFixIt(key)
      res.status(200).json({
        verdict: true,
        explanation
      })
    } else {
      accuracy.storeFixItVerdict(key, false)
      res.status(200).json({
        verdict: false,
        explanation
      })
    }
  }
}
