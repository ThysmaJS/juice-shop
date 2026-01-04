/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { reviewsCollection } from '../data/mongodb'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function createProductReviews () {
  return async (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req)
    challengeUtils.solveIf(
      challenges.forgedReviewChallenge,
      () => user?.data?.email !== req.body.author
    )

    try {
      // Validation & sanitisation basiques pour éviter l'injection NoSQL
      const productId = String(req.params.id || '')
      const message = typeof req.body.message === 'string' ? req.body.message.substring(0, 500) : ''
      const author = typeof req.body.author === 'string' ? req.body.author : ''

      // Rejeter valeurs contenant opérateurs Mongo-like
      const containsNoSqlOperator = (v: string) => v.includes('$') || v.includes('.')
      if (!productId || !message || !author || containsNoSqlOperator(productId) || containsNoSqlOperator(author)) {
        return res.status(400).json({ error: 'Invalid review payload' })
      }

      await reviewsCollection.insert({
        product: productId,
        message,
        author,
        likesCount: 0,
        likedBy: []
      })
      return res.status(201).json({ status: 'success' })
    } catch (err: unknown) {
      return res.status(500).json(utils.getErrorMessage(err))
    }
  }
}
