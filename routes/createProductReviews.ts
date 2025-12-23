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

    // Security fix: Comprehensive input validation and sanitization
    const productId = req.params.id
    const message = req.body.message
    const author = req.body.author

    // Validate product ID
    if (!productId || typeof productId !== 'string') {
      return res.status(400).json({ error: 'Invalid product ID' })
    }

    // Validate and sanitize message
    if (!message || typeof message !== 'string') {
      return res.status(400).json({ error: 'Invalid message format' })
    }
    
    // Message length restriction
    if (message.length > 5000) {
      return res.status(400).json({ error: 'Message too long (max 5000 characters)' })
    }

    // Comprehensive HTML sanitization to prevent XSS
    const sanitizedMessage = security.sanitizeHtml(message.trim())

    // Validate author
    if (!author || typeof author !== 'string') {
      return res.status(400).json({ error: 'Invalid author format' })
    }

    // Author length restriction
    if (author.length > 200) {
      return res.status(400).json({ error: 'Author name too long (max 200 characters)' })
    }

    // Sanitize author name
    const sanitizedAuthor = security.sanitizeHtml(author.trim())

    try {
      // Use sanitized and validated data for database insertion
      await reviewsCollection.insert({
        product: productId,
        message: sanitizedMessage,
        author: sanitizedAuthor,
        likesCount: 0,
        likedBy: []
      })
      return res.status(201).json({ status: 'success' })
    } catch (err: unknown) {
      return res.status(500).json({ error: 'Internal server error' })
    }
  }
}
