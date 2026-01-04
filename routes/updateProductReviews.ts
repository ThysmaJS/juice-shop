/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    const id = String(req.body.id || '')
    const message = typeof req.body.message === 'string' ? req.body.message.substring(0, 500) : ''

    // Validation basique pour éviter NoSQL operator injection et mises à jour massives
    if (!user || !id || id.includes('$') || id.includes('.') || !message) {
      return res.status(400).json({ error: 'Invalid payload' })
    }

    db.reviewsCollection.update(
      { _id: id, author: user.data.email }, // Contraindre à l’auteur
      { $set: { message } },
      { multi: false }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
// vuln-code-snippet end noSqlReviewsChallenge forgedReviewChallenge
