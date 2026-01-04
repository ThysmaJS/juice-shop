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
      // Validation & sanitisation pour éviter l'injection NoSQL
      const rawProductId = String(req.params.id ?? '')
      const rawMessage = typeof req.body.message === 'string' ? req.body.message : ''
      const rawAuthor = typeof req.body.author === 'string' ? req.body.author : ''

      // Rejeter valeurs contenant opérateurs Mongo-like
      const containsNoSqlOperator = (v: string) => v.includes('$') || v.includes('.')
      const sanitizeText = (v: string) => {
        // Remove control characters without embedding them in the literal
        const cleaned = v
          .split('')
          .filter(ch => {
            const code = ch.charCodeAt(0)
            return code >= 32 && code !== 127 && !('<>$'.includes(ch))
          })
          .join('')
        return cleaned.substring(0, 500)
      }

      // productId doit être numérique et non vide
      const productIdNum = Number.parseInt(rawProductId, 10)
      const message = sanitizeText(rawMessage)
      const author = sanitizeText(rawAuthor)

      if (!Number.isFinite(productIdNum) || String(productIdNum) !== rawProductId || message.length === 0 || author.length === 0) {
        return res.status(400).json({ error: 'Invalid review payload' })
      }
      if (containsNoSqlOperator(rawProductId) || containsNoSqlOperator(rawMessage) || containsNoSqlOperator(rawAuthor)) {
        return res.status(400).json({ error: 'Invalid characters in payload' })
      }

      // Construire un document strictement typé avec champs autorisés uniquement
      const reviewDoc = {
        product: productIdNum,
        message,
        author,
        likesCount: 0,
        likedBy: [] as string[]
      }

      await reviewsCollection.insert(reviewDoc)
      return res.status(201).json({ status: 'success' })
    } catch (err: unknown) {
      return res.status(500).json(utils.getErrorMessage(err))
    }
  }
}
