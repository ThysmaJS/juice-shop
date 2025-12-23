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

    // Input validation and sanitization
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
    
    // Message length restriction to prevent DoS
    if (message.length > 5000) {
      return res.status(400).json({ error: 'Message too long (max 5000 characters)' })
    }

    // Sanitize message to prevent XSS and injection attacks
    const sanitizedMessage = message
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove script tags
      .replace(/<[^>]*>/g, '') // Remove HTML tags
      .trim()

    // Validate author
    if (!author || typeof author !== 'string') {
      return res.status(400).json({ error: 'Invalid author format' })
    }

    // Author length restriction
    if (author.length > 200) {
      return res.status(400).json({ error: 'Author name too long (max 200 characters)' })
    }

    // Sanitize author to prevent injection
    const sanitizedAuthor = author
      .replace(/<[^>]*>/g, '') // Remove HTML tags
      .replace(/[<>'"\\]/g, '') // Remove potentially dangerous characters
      .trim()

    // Validate product ID format (assuming numeric or alphanumeric)
    if (!/^[a-zA-Z0-9\-_]+$/.test(productId)) {
      return res.status(400).json({ error: 'Invalid product ID format' })
    }

    try {
      // Use sanitized and validated data for database insertion
      await reviewsCollection.insert({
        product: productId,
        message: sanitizedMessage,
        author: sanitizedAuthor,
        likesCount: 0,
        likedBy: [],
        // Add metadata for security tracking
        createdAt: new Date(),
        ipAddress: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown'
      })
      return res.status(201).json({ status: 'success' })
    } catch (err: unknown) {
      // Enhanced error logging for security monitoring
      console.error('Database insertion error:', {
        error: utils.getErrorMessage(err),
        productId,
        author: sanitizedAuthor,
        timestamp: new Date().toISOString(),
        ip: req.ip
      })
      return res.status(500).json({ error: 'Internal server error' })
    }
  }
}
