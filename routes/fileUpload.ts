/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import os from 'node:os'
import fs from 'node:fs'
import vm from 'node:vm'
import path from 'node:path'
import yaml from 'js-yaml'
import libxml from 'libxmljs2'
import unzipper from 'unzipper'
import { type NextFunction, type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    next()
  } else {
    return res.status(400).json({ error: 'File is not passed' })
  }
}

function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.fileWriteChallenge)) {
      const buffer = file.buffer
      const filename = file.originalname.toLowerCase()
      
      // Enhanced filename validation
      if (!/^[a-zA-Z0-9._-]+\.zip$/.test(filename)) {
        return res.status(400).json({ error: 'Invalid filename format' })
      }
      
      const tempFile = path.join(os.tmpdir(), filename)
      fs.open(tempFile, 'w', function (err, fd) {
        if (err != null) { next(err) }
        fs.write(fd, buffer, 0, buffer.length, null, function (err) {
          if (err != null) { next(err) }
          fs.close(fd, function () {
            fs.createReadStream(tempFile)
              .pipe(unzipper.Parse())
              .on('entry', function (entry: any) {
                const fileName = entry.path
                
                // Enhanced path traversal protection
                if (!fileName || typeof fileName !== 'string') {
                  entry.autodrain()
                  return
                }
                
                // Normalize and validate the filename to prevent path traversal
                const normalizedFileName = path.normalize(fileName)
                
                // Block path traversal attempts (../, ..\, absolute paths)
                if (normalizedFileName.includes('..') || 
                    path.isAbsolute(normalizedFileName) || 
                    normalizedFileName.startsWith('/') ||
                    normalizedFileName.startsWith('\\') ||
                    normalizedFileName.includes('\0')) {
                  console.warn('Path traversal attempt blocked:', normalizedFileName)
                  entry.autodrain()
                  return
                }
                
                // Only allow safe characters in filename
                if (!/^[a-zA-Z0-9._/-]+$/.test(normalizedFileName)) {
                  console.warn('Invalid filename characters detected:', normalizedFileName)
                  entry.autodrain()
                  return
                }
                
                // Ensure filename length is reasonable
                if (normalizedFileName.length > 255) {
                  console.warn('Filename too long:', normalizedFileName)
                  entry.autodrain()
                  return
                }
                
                const safeFileName = path.basename(normalizedFileName)
                const uploadsDir = path.resolve('uploads/complaints')
                const absolutePath = path.resolve(uploadsDir, safeFileName)
                
                // Double-check that the resolved path is still within the uploads directory
                if (!absolutePath.startsWith(uploadsDir + path.sep) && absolutePath !== uploadsDir) {
                  console.warn('Path traversal detected after resolution:', absolutePath)
                  entry.autodrain()
                  return
                }
                
                // Original challenge logic (for educational purposes)
                challengeUtils.solveIf(challenges.fileWriteChallenge, () => { 
                  return absolutePath === path.resolve('ftp/legal.md') 
                })
                
                // Create the safe file path for writing
                const safePath = path.join('uploads/complaints', safeFileName)
                
                // Additional safety check
                if (path.resolve(safePath).startsWith(path.resolve('uploads/complaints'))) {
                  entry.pipe(fs.createWriteStream(safePath).on('error', function (err) { 
                    console.error('File write error:', err)
                    next(err) 
                  }))
                } else {
                  entry.autodrain()
                }
              }).on('error', function (err: unknown) { 
                console.error('Unzip error:', err)
                next(err) 
              })
          })
        })
      })
    }
    res.status(204).end()
  } else {
    next()
  }
}

function checkUploadSize ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    challengeUtils.solveIf(challenges.uploadSizeChallenge, () => { return file?.size > 100000 })
  }
  next()
}

function checkFileType ({ file }: Request, res: Response, next: NextFunction) {
  const fileType = file?.originalname.substr(file.originalname.lastIndexOf('.') + 1).toLowerCase()
  challengeUtils.solveIf(challenges.uploadTypeChallenge, () => {
    return !(fileType === 'pdf' || fileType === 'xml' || fileType === 'zip' || fileType === 'yml' || fileType === 'yaml')
  })
  next()
}

function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.xml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) { // XXE attacks in Docker/Heroku containers regularly cause "segfault" crashes
      const data = file.buffer.toString()
      
      // Input validation and size limits
      if (data.length > 1000000) { // 1MB limit
        res.status(413)
        return next(new Error('File too large for processing'))
      }
      
      // Basic XML validation to prevent malformed input
      if (!data.trim().startsWith('<') || !data.includes('>')) {
        res.status(400)
        return next(new Error('Invalid XML format'))
      }
      
      try {
        // Enhanced sandbox with limited context
        const restrictedSandbox = { 
          libxml,
          data,
          // Provide safe alternatives only
          console: {
            log: () => {}, // Disabled for security
            error: () => {} // Disabled for security
          }
        }
        
        const context = vm.createContext(restrictedSandbox)
        Object.freeze(context) // Prevent runtime modification
        
        const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', context, { 
          timeout: 2000,
          breakOnSigint: true,
          displayErrors: false
        })
        
        const xmlString = xmlDoc.toString(false)
        
        // Limit output size to prevent information disclosure
        const truncatedXmlString = utils.trunc(xmlString, 400)
        
        challengeUtils.solveIf(challenges.xxeFileDisclosureChallenge, () => { 
          return (utils.matchesEtcPasswdFile(xmlString) || utils.matchesSystemIniFile(xmlString)) 
        })
        
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + truncatedXmlString + ' (' + file.originalname + ')'))
      } catch (err: any) { // TODO: Remove any
        if (utils.contains(err.message, 'Script execution timed out')) {
          if (challengeUtils.notSolved(challenges.xxeDosChallenge)) {
            challengeUtils.solve(challenges.xxeDosChallenge)
          }
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          // Sanitize error message to prevent information leakage
          const sanitizedError = err.message.replace(/\/[^\/\s]+/g, '[PATH]') // Hide file paths
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + sanitizedError + ' (' + file.originalname + ')'))
        }
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
    }
  }
  next()
}

function handleYamlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.yml') || utils.endsWith(file?.originalname.toLowerCase(), '.yaml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) {
      const data = file.buffer.toString()
      
      // Input validation and size limits
      if (data.length > 500000) { // 500KB limit to prevent YAML bombs
        res.status(413)
        return next(new Error('YAML file too large for processing'))
      }
      
      // Basic YAML format validation
      if (!data.trim() || data.length < 3) {
        res.status(400)
        return next(new Error('Invalid YAML format'))
      }
      
      try {
        // Enhanced sandbox with restricted context
        const restrictedSandbox = { 
          yaml,
          data,
          JSON, // Required for JSON.stringify
          // Disable dangerous globals
          console: {
            log: () => {},
            error: () => {}
          }
        }
        
        const context = vm.createContext(restrictedSandbox)
        Object.freeze(context) // Prevent runtime modification
        
        const yamlString = vm.runInContext('JSON.stringify(yaml.load(data))', context, { 
          timeout: 2000,
          breakOnSigint: true,
          displayErrors: false
        })
        
        // Limit output size
        const truncatedYamlString = utils.trunc(yamlString, 400)
        
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + truncatedYamlString + ' (' + file.originalname + ')'))
      } catch (err: any) { // TODO: Remove any
        if (utils.contains(err.message, 'Invalid string length') || utils.contains(err.message, 'Script execution timed out')) {
          if (challengeUtils.notSolved(challenges.yamlBombChallenge)) {
            challengeUtils.solve(challenges.yamlBombChallenge)
          }
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          // Sanitize error message to prevent information leakage
          const sanitizedError = err.message.replace(/\/[^\/\s]+/g, '[PATH]').substring(0, 200)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + sanitizedError + ' (' + file.originalname + ')'))
        }
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
    }
  }
  res.status(204).end()
}

export {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload,
  handleYamlUpload
}
