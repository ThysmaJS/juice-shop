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
    // Security fix: Remove code execution completely to prevent RCE
    const orderLinesData = body.orderLinesData || ''
    
    // Input validation
    if (typeof orderLinesData !== 'string') {
      return res.status(400).json({ error: 'Invalid orderLinesData format' })
    }
    
    // Parse JSON safely instead of executing code
    try {
      const orderLines = JSON.parse(orderLinesData)
      
      if (!Array.isArray(orderLines)) {
        return res.status(400).json({ error: 'orderLinesData must be a JSON array' })
      }
      
      // Process the order data safely
      const processedOrder = orderLines.map((line: any, index: number) => ({
        lineNumber: index + 1,
        product: line.product || 'Unknown',
        quantity: parseInt(line.quantity) || 0,
        price: parseFloat(line.price) || 0
      }))
      
      res.json({ 
        cid: body.cid,
        orderNo: uniqueOrderNumber(),
        paymentDue: dateTwoWeeksFromNow(),
        orderLines: processedOrder
      })
      
    } catch (jsonError) {
      return res.status(400).json({ error: 'Invalid JSON format' })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
