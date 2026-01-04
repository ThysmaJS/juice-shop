/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = String(req.body.imageUrl)
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          // Validate remote image URL strictly against an exact allowlist of URLs
          // If PROFILE_IMAGE_ALLOWED_URLS is not provided, remote image fetching is blocked
          const allowedUrls = new Set((process.env.PROFILE_IMAGE_ALLOWED_URLS ?? '').split(',').map(u => u.trim()).filter(Boolean))
          if (allowedUrls.size === 0) {
            throw new Error('Remote image fetching disabled')
          }
          let parsed: URL
          try {
            parsed = new URL(url)
          } catch {
            throw new Error('Invalid image URL')
          }
          const finalUrl = [...allowedUrls].find(u => u === parsed.toString())
          if (!finalUrl) {
            throw new Error('Remote image URL not allowed')
          }

          const response = await fetch(finalUrl)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(new URL(finalUrl).pathname.split('.').slice(-1)[0].toLowerCase()) ? new URL(finalUrl).pathname.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
        } catch (error) {
          // Do not set arbitrary external URLs as profile images
          logger.warn(`Blocked external profile image: ${utils.getErrorMessage(error)}`)
          res.status(400).json({ error: 'Invalid profile image URL' })
          return
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
