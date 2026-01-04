/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import express, { type NextFunction, type Request, type Response } from 'express'
import path from 'node:path'

import { SecurityQuestionModel } from '../models/securityQuestion'
import { PrivacyRequestModel } from '../models/privacyRequests'
import { SecurityAnswerModel } from '../models/securityAnswer'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'

const router = express.Router()

router.get('/', async (req: Request, res: Response, next: NextFunction) => {
  const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
  if (!loggedInUser) {
    next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    return
  }
  const email = loggedInUser.data.email

  try {
    const answer = await SecurityAnswerModel.findOne({
      include: [{
        model: UserModel,
        where: { email }
      }]
    })
    if (answer == null) {
      throw new Error('No answer found!')
    }
    const question = await SecurityQuestionModel.findByPk(answer.SecurityQuestionId)
    if (question == null) {
      throw new Error('No question found!')
    }

    res.render('dataErasureForm', { userEmail: email, securityQuestion: question.question })
  } catch (error) {
    next(error)
  }
})

interface DataErasureRequestParams {
  layout?: string
  email: string
  securityAnswer: string
}

// eslint-disable-next-line @typescript-eslint/no-misused-promises
router.post('/', async (req: Request<Record<string, unknown>, Record<string, unknown>, DataErasureRequestParams>, res: Response, next: NextFunction): Promise<void> => {
  const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
  if (!loggedInUser) {
    next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    return
  }

  try {
    await PrivacyRequestModel.create({
      UserId: loggedInUser.data.id,
      deletionRequested: true
    })

    res.clearCookie('token')
    const allowedLayouts = ['main', 'plain']
    const requestedLayout = typeof req.body.layout === 'string' ? req.body.layout : undefined
    const isValidName = (name: string) => /^[a-z0-9_-]+$/i.test(name)

    let layout: string | undefined
    if (requestedLayout && isValidName(requestedLayout) && allowedLayouts.includes(requestedLayout)) {
      layout = requestedLayout
    }

    res.render('dataErasureResult', {
      // Copier les champs non sensibles
      email: req.body.email,
      securityAnswer: req.body.securityAnswer,
      // Appliquer éventuellement un layout valide, jamais un chemin
      layout
    })
  } catch (error) {
    next(error)
  }
})

export default router
