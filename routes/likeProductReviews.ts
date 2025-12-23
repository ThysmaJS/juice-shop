/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { type Review } from '../data/types'
import * as db from '../data/mongodb'

const sleep = async (ms: number) => await new Promise(resolve => setTimeout(resolve, ms))

export function likeProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const id = req.body.id
    const user = security.authenticatedUsers.from(req)
    // Security fix: Comprehensive input validation and sanitization
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    if (!id) {
      return res.status(400).json({ error: 'Missing review ID' })
    }

    // Validate ID format - should be a string for MongoDB ObjectId
    if (typeof id !== 'string') {
      return res.status(400).json({ error: 'Invalid review ID format' })
    }

    // Sanitize ID to prevent NoSQL injection
    const sanitizedId = id.toString().trim()
    
    // Validate MongoDB ObjectId format (24 hex characters)
    if (!/^[a-fA-F0-9]{24}$/.test(sanitizedId)) {
      return res.status(400).json({ error: 'Invalid review ID format' })
    }

    try {
      // Use sanitized ID in database queries
      const review = await db.reviewsCollection.findOne({ _id: sanitizedId })
      if (!review) {
        return res.status(404).json({ error: 'Not found' })
      }

      // Validate likedBy array exists and is an array
      const likedBy = Array.isArray(review.likedBy) ? review.likedBy : []
      
      // Validate user email
      if (!user.data?.email || typeof user.data.email !== 'string') {
        return res.status(400).json({ error: 'Invalid user data' })
      }

      if (likedBy.includes(user.data.email)) {
        return res.status(403).json({ error: 'Not allowed' })
      }

      // Use sanitized ID in update operations
      await db.reviewsCollection.update(
        { _id: sanitizedId },
        { $inc: { likesCount: 1 } }
      )

      // Artificial wait for timing attack challenge
      await sleep(150)
      
      try {
        const updatedReview: Review = await db.reviewsCollection.findOne({ _id: sanitizedId })
        
        if (!updatedReview) {
          return res.status(404).json({ error: 'Review not found after update' })
        }

        const updatedLikedBy = Array.isArray(updatedReview.likedBy) ? [...updatedReview.likedBy] : []
        updatedLikedBy.push(user.data.email)

        const count = updatedLikedBy.filter(email => email === user.data.email).length
        challengeUtils.solveIf(challenges.timingAttackChallenge, () => count > 2)

        const result = await db.reviewsCollection.update(
          { _id: sanitizedId },
          { $set: { likedBy: updatedLikedBy } }
        )
        
        // Sanitize response to prevent information leakage
        const sanitizedResult = {
          acknowledged: result.acknowledged || false,
          modifiedCount: result.modifiedCount || 0
        }
        
        res.json(sanitizedResult)
      } catch (err) {
        console.error('Database update error:', err)
        res.status(500).json({ error: 'Internal server error' })
      }
    } catch (err) {
      console.error('Database query error:', err)
      res.status(400).json({ error: 'Wrong Params' })
    }
  }
}
