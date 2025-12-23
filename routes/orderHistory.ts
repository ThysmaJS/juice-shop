/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { ordersCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'

export function orderHistory () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.headers?.authorization?.replace('Bearer ', ''))
    if (loggedInUser?.data?.email && loggedInUser.data.id) {
      const email = loggedInUser.data.email
      
      // Security fix: Enhanced email validation and sanitization
      if (typeof email !== 'string' || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' })
      }
      
      // Additional security: Sanitize email to prevent injection
      const sanitizedEmail = email.toLowerCase().trim()
      
      // Apply the vowel replacement in a secure manner
      const updatedEmail = sanitizedEmail.replace(/[aeiou]/gi, '*')
      
      // Use parameterized query equivalent for MongoDB
      const order = await ordersCollection.find({ 
        email: { $eq: updatedEmail } 
      })
      res.status(200).json({ status: 'success', data: order })
    } else {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}

export function allOrders () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const order = await ordersCollection.find()
    res.status(200).json({ status: 'success', data: order.reverse() })
  }
}

export function toggleDeliveryStatus () {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Security fix: Validate order ID
    const orderId = req.params.id
    if (!orderId || typeof orderId !== 'string') {
      return res.status(400).json({ error: 'Invalid order ID' })
    }
    
    // Validate MongoDB ObjectId format (24 hex characters)
    if (!/^[a-fA-F0-9]{24}$/.test(orderId)) {
      return res.status(400).json({ error: 'Invalid order ID format' })
    }
    
    // Validate delivery status from request body
    if (typeof req.body.deliveryStatus !== 'boolean') {
      return res.status(400).json({ error: 'Invalid delivery status format' })
    }
    
    const deliveryStatus = !req.body.deliveryStatus
    const eta = deliveryStatus ? '0' : '1'
    await ordersCollection.update({ _id: orderId }, { $set: { delivered: deliveryStatus, eta } })
    res.status(200).json({ status: 'success' })
  }
}
