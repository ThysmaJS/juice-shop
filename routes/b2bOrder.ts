/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'
// @ts-expect-error FIXME due to non-existing type definitions for notevil
import { eval as safeEval } from 'notevil'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = body.orderLinesData || ''
      
      // Input validation and sanitization
      if (typeof orderLinesData !== 'string') {
        return res.status(400).json({ error: 'Invalid orderLinesData format' })
      }
      
      // Length restriction to prevent DoS
      if (orderLinesData.length > 10000) {
        return res.status(400).json({ error: 'orderLinesData too large' })
      }
      
      // Basic blacklist for dangerous patterns (while maintaining challenge functionality)
      const dangerousPatterns = [
        /require\s*\(\s*['"`]child_process['"`]\s*\)/,
        /require\s*\(\s*['"`]fs['"`]\s*\)/,
        /require\s*\(\s*['"`]os['"`]\s*\)/,
        /process\s*\.\s*exit/,
        /global\s*\./,
        /__dirname/,
        /__filename/
      ]
      
      const containsDangerousCode = dangerousPatterns.some(pattern => pattern.test(orderLinesData))
      if (containsDangerousCode) {
        return res.status(400).json({ error: 'Potentially dangerous code detected' })
      }
      
      try {
        // More restricted sandbox with limited context
        const restrictedSandbox = { 
          safeEval,
          orderLinesData,
          // Provide safe alternatives
          Math,
          Date,
          JSON,
          String,
          Number,
          Boolean,
          Array,
          Object
        }
        
        const context = vm.createContext(restrictedSandbox)
        
        // Additional security: freeze the context to prevent modification
        Object.freeze(context)
        
        vm.runInContext('safeEval(orderLinesData)', context, { 
          timeout: 2000,
          breakOnSigint: true,
          // Additional VM options for security
          displayErrors: false
        })
        
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
          challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
          next(err)
        }
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
