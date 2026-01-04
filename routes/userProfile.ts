/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'
import config from 'config'
import pug from 'pug'
import fs from 'node:fs/promises'

import * as challengeUtils from '../lib/challengeUtils'
import { themes } from '../views/themes/themes'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const entities = new Entities()

function favicon () {
  return utils.extractFilename(config.get('application.favicon'))
}

export function getUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    let template: string
    try {
      template = await fs.readFile('views/userProfile.pug', { encoding: 'utf-8' })
    } catch (err) {
      next(err)
      return
    }

    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress)); return
    }

    let user: UserModel | null
    try {
      user = await UserModel.findByPk(loggedInUser.data.id)
    } catch (error) {
      next(error)
      return
    }

    if (!user) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    // Sanitize and strictly treat username as text, never as code
    const rawUsername = String(user.username ?? '')
    const username = entities.encode(rawUsername)

    const themeKey = config.get<string>('application.theme') as keyof typeof themes
    const theme = themes[themeKey] || themes['bluegrey-lightgreen']

    if (username) {
      template = template.replace(/_username_/g, username)
    }
    template = template.replace(/_emailHash_/g, security.hash(user?.email))
    template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
    template = template.replace(/_favicon_/g, favicon())
    template = template.replace(/_bgColor_/g, theme.bgColor)
    template = template.replace(/_textColor_/g, theme.textColor)
    template = template.replace(/_navColor_/g, theme.navColor)
    template = template.replace(/_primLight_/g, theme.primLight)
    template = template.replace(/_primDark_/g, theme.primDark)
    template = template.replace(/_logo_/g, utils.extractFilename(config.get('application.logo')))

    try {
      const fn = pug.compile(template)
      // Restrict img-src to self plus optional allowed external hosts
      const allowedHosts = new Set((process.env.PROFILE_IMAGE_ALLOWED_HOSTS ?? '').split(',').map(h => h.trim()).filter(Boolean))
      let imgSrc = `'self'`
      try {
        if (user?.profileImage) {
          const parsed = new URL(user.profileImage)
          const isPrivateHost = /^(localhost|127\.0\.0\.1)$/i.test(parsed.hostname) || /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(parsed.hostname)
          if (parsed.protocol === 'https:' && !isPrivateHost && (allowedHosts.size === 0 || allowedHosts.has(parsed.hostname))) {
            imgSrc += ` ${parsed.origin}`
          }
        }
      } catch {}
      const CSP = `img-src ${imgSrc}; script-src 'self' https://code.getmdl.io http://ajax.googleapis.com`

      challengeUtils.solveIf(challenges.usernameXssChallenge, () => {
        return username && user?.profileImage.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null && utils.contains(username, '<script>alert(`xss`)</script>')
      })

      res.set({
        'Content-Security-Policy': CSP
      })

      // Pass only safe fields
      res.send(fn({
        username,
        email: user?.email,
        profileImage: user?.profileImage
      }))
    } catch (err) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}
