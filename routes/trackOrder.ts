/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as utils from '../lib/utils'
import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'

export function trackOrder () {
  return (req: Request, res: Response) => {
    // Security fix: Validate and sanitize order ID
    const id = req.params.id
    
    if (!id || typeof id !== 'string') {
      return res.status(400).json({ error: 'Invalid order ID' })
    }
    
    // Validate order ID format and sanitize
    let orderId: string
    if (/^[A-Za-z0-9_-]+$/.test(id)) {
      // Only allow alphanumeric characters, underscore and dash
      orderId = id.slice(0, 60) // Limit length
    } else {
      return res.status(400).json({ error: 'Invalid order ID format' })
    }

    challengeUtils.solveIf(challenges.reflectedXssChallenge, () => { return utils.contains(orderId, '<iframe src="javascript:alert(`xss`)">') })
    
    // Security fix: Use secure query instead of $where with code execution
    db.ordersCollection.find({ orderId: orderId }).then((order: any) => {
      const result = utils.queryResultToJson(order)
      challengeUtils.solveIf(challenges.noSqlOrdersChallenge, () => { return result.data.length > 1 })
      if (result.data[0] === undefined) {
        result.data[0] = { orderId: orderId }
      }
      res.json(result)
    }, () => {
      res.status(400).json({ error: 'Wrong Param' })
    })
  }
}
