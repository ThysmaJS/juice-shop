/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import config from 'config'
import PDFDocument from 'pdfkit'
import { type Request, type Response, type NextFunction } from 'express'

import { challenges, products } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import { BasketItemModel } from '../models/basketitem'
import { DeliveryModel } from '../models/delivery'
import { QuantityModel } from '../models/quantity'
import { ProductModel } from '../models/product'
import { BasketModel } from '../models/basket'
import { WalletModel } from '../models/wallet'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'
import * as db from '../data/mongodb'

interface Product {
  quantity: number
  id?: number
  name: string
  price: number
  total: number
  bonus: number
}

export function placeOrder () {
  return (req: Request, res: Response, next: NextFunction) => {
    const id = req.params.id
    BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })
      .then(async (basket: BasketModel | null) => {
        if (basket != null) {
          const customer = security.authenticatedUsers.from(req)
          const email = customer ? customer.data ? customer.data.email : '' : ''
          const orderId = security.hash(email).slice(0, 4) + '-' + utils.randomHexString(16)
          const pdfFile = `order_${orderId}.pdf`
          const doc = new PDFDocument()
          const date = new Date().toJSON().slice(0, 10)
          const fileWriter = doc.pipe(fs.createWriteStream(path.join('ftp/', pdfFile)))

          fileWriter.on('finish', async () => {
            void basket.update({ coupon: null })
            await BasketItemModel.destroy({ where: { BasketId: id } })
            res.json({ orderConfirmation: orderId })
          })

          doc.font('Times-Roman').fontSize(40).text(config.get<string>('application.name'), { align: 'center' })
          doc.moveTo(70, 115).lineTo(540, 115).stroke()
          doc.moveTo(70, 120).lineTo(540, 120).stroke()
          doc.fontSize(20).moveDown()
          doc.font('Times-Roman').fontSize(20).text(req.__('Order Confirmation'), { align: 'center' })
          doc.fontSize(20).moveDown()
          doc.font('Times-Roman').fontSize(15).text(`${req.__('Customer')}: ${email}`, { align: 'left' })
          doc.font('Times-Roman').fontSize(15).text(`${req.__('Order')} #: ${orderId}`, { align: 'left' })
          doc.moveDown()
          doc.font('Times-Roman').fontSize(15).text(`${req.__('Date')}: ${date}`, { align: 'left' })
          doc.moveDown()
          doc.moveDown()
          let totalPrice = 0
          const basketProducts: Product[] = []
          let totalPoints = 0
          basket.Products?.forEach(({ BasketItem, price, deluxePrice, name, id }) => {
            if (BasketItem != null) {
              challengeUtils.solveIf(challenges.christmasSpecialChallenge, () => { return BasketItem.ProductId === products.christmasSpecial.id })
              QuantityModel.findOne({ where: { ProductId: BasketItem.ProductId } }).then((product: any) => {
                const newQuantity = product.quantity - BasketItem.quantity
                QuantityModel.update({ quantity: newQuantity }, { where: { ProductId: BasketItem?.ProductId } }).catch((error: unknown) => {
                  next(error)
                })
              }).catch((error: unknown) => {
                next(error)
              })
              let itemPrice: number
              if (security.isDeluxe(req)) {
                itemPrice = deluxePrice
              } else {
                itemPrice = price
              }
              const itemTotal = itemPrice * BasketItem.quantity
              const itemBonus = Math.round(itemPrice / 10) * BasketItem.quantity
              const product = {
                quantity: BasketItem.quantity,
                id,
                name: req.__(name),
                price: itemPrice,
                total: itemTotal,
                bonus: itemBonus
              }
              basketProducts.push(product)
              doc.text(`${BasketItem.quantity}x ${req.__(name)} ${req.__('ea.')} ${itemPrice} = ${itemTotal}¤`)
              doc.moveDown()
              totalPrice += itemTotal
              totalPoints += itemBonus
            }
          })
          doc.moveDown()
          const discount = calculateApplicableDiscount(basket, req) ?? 0
          let discountAmount = '0'
          if (discount > 0) {
            discountAmount = (totalPrice * (discount / 100)).toFixed(2)
            doc.text(discount + '% discount from coupon: -' + discountAmount + '¤')
            doc.moveDown()
            totalPrice -= parseFloat(discountAmount)
          }
          const deliveryMethod = {
            deluxePrice: 0,
            price: 0,
            eta: 5
          }
          if (req.body.orderDetails?.deliveryMethodId) {
            const deliveryMethodFromModel = await DeliveryModel.findOne({ where: { id: req.body.orderDetails.deliveryMethodId } })
            if (deliveryMethodFromModel != null) {
              deliveryMethod.deluxePrice = deliveryMethodFromModel.deluxePrice
              deliveryMethod.price = deliveryMethodFromModel.price
              deliveryMethod.eta = deliveryMethodFromModel.eta
            }
          }
          const deliveryAmount = security.isDeluxe(req) ? deliveryMethod.deluxePrice : deliveryMethod.price
          totalPrice += deliveryAmount
          doc.text(`${req.__('Delivery Price')}: ${deliveryAmount.toFixed(2)}¤`)
          doc.moveDown()
          doc.font('Helvetica-Bold').fontSize(20).text(`${req.__('Total Price')}: ${totalPrice.toFixed(2)}¤`)
          doc.moveDown()
          doc.font('Helvetica-Bold').fontSize(15).text(`${req.__('Bonus Points Earned')}: ${totalPoints}`)
          doc.font('Times-Roman').fontSize(15).text(`(${req.__('The bonus points from this order will be added 1:1 to your wallet ¤-fund for future purchases!')}`)
          doc.moveDown()
          doc.moveDown()
          doc.font('Times-Roman').fontSize(15).text(req.__('Thank you for your order!'))

          challengeUtils.solveIf(challenges.negativeOrderChallenge, () => { return totalPrice < 0 })

          if (req.body.UserId) {
            if (req.body.orderDetails && req.body.orderDetails.paymentId === 'wallet') {
              const wallet = await WalletModel.findOne({ where: { UserId: req.body.UserId } })
              if ((wallet != null) && wallet.balance >= totalPrice) {
                WalletModel.decrement({ balance: totalPrice }, { where: { UserId: req.body.UserId } }).catch((error: unknown) => {
                  next(error)
                })
              } else {
                next(new Error('Insufficient wallet balance.'))
              }
            }
            WalletModel.increment({ balance: totalPoints }, { where: { UserId: req.body.UserId } }).catch((error: unknown) => {
              next(error)
            })
          }

          // Sanitize user-controlled orderDetails fields before insert
          const paymentId = req.body.orderDetails && typeof req.body.orderDetails.paymentId === 'string' ? req.body.orderDetails.paymentId : null
          const addressId = req.body.orderDetails && (typeof req.body.orderDetails.addressId === 'string' || typeof req.body.orderDetails.addressId === 'number') ? req.body.orderDetails.addressId : null
          if (paymentId && paymentId !== 'wallet' && paymentId !== 'card') {
            return next(new Error('Unsupported payment method'))
          }
          // Map basket products to a safe subset of fields
          const safeProducts = basketProducts.map(p => ({
            quantity: Number.isFinite(p.quantity) ? p.quantity : 0,
            id: typeof p.id === 'number' ? p.id : null,
            name: String(p.name),
            price: Number.isFinite(p.price) ? p.price : 0,
            total: Number.isFinite(p.total) ? p.total : 0,
            bonus: Number.isFinite(p.bonus) ? p.bonus : 0
          }))

          // Defensive check to avoid NoSQL operator injection in any string
          const hasNoSqlOperators = (val: unknown): boolean => {
            if (typeof val === 'string') return val.includes('$') || val.includes('.')
            if (Array.isArray(val)) return val.some(v => hasNoSqlOperators(v))
            if (val && typeof val === 'object') {
              return Object.keys(val as Record<string, unknown>).some(k => k.includes('$') || k.includes('.')) ||
                Object.values(val as Record<string, unknown>).some(v => hasNoSqlOperators(v))
            }
            return false
          }

          // Additional strict validation for order payload types and formats
          const isValidCurrency = (v: unknown): boolean => typeof v === 'string' && /^\d+(\.\d{1,2})?$/.test(v)
          const isPositiveNumber = (v: unknown): boolean => typeof v === 'number' && Number.isFinite(v) && v >= 0
          const isValidEtaString = (v: unknown): boolean => typeof v === 'string' && /^\d+$/.test(v)
          const isValidOrderId = (v: unknown): boolean => typeof v === 'string' && /^[a-f0-9]{4}-[a-f0-9]{16}$/i.test(v)

          const orderDoc = {
            promotionalAmount: discountAmount,
            paymentId,
            addressId: typeof addressId === 'number' ? addressId : null,
            orderId,
            delivered: false,
            email: (email ? email.replace(/[aeiou]/gi, '*') : undefined),
            totalPrice,
            products: safeProducts,
            bonus: totalPoints,
            deliveryPrice: deliveryAmount,
            eta: deliveryMethod.eta.toString()
          }

          // Validate final document before inserting
          if (hasNoSqlOperators(orderDoc)) {
            return next(new Error('Invalid characters in order payload'))
          }
          if (!isValidCurrency(orderDoc.promotionalAmount)) {
            return next(new Error('Invalid promotional amount'))
          }
          if (!isValidOrderId(orderDoc.orderId)) {
            return next(new Error('Invalid order id'))
          }
          if (!isPositiveNumber(orderDoc.totalPrice)) {
            return next(new Error('Invalid total price'))
          }
          if (!isValidEtaString(orderDoc.eta)) {
            return next(new Error('Invalid ETA format'))
          }
          if (!['wallet', 'card', null].includes(orderDoc.paymentId as any)) {
            return next(new Error('Invalid payment method'))
          }
          if (orderDoc.products.some(p => !isPositiveNumber(p.price) || !isPositiveNumber(p.total) || !Number.isInteger(p.quantity))) {
            return next(new Error('Invalid product data'))
          }

          db.insertSafeOrder(Object.freeze(orderDoc)).then(() => {
            doc.end()
          })
        } else {
          next(new Error(`Basket with id=${id} does not exist.`))
        }
      }).catch((error: unknown) => {
        next(error)
      })
  }
}

function calculateApplicableDiscount (basket: BasketModel, req: Request) {
  if (security.discountFromCoupon(basket.coupon ?? undefined)) {
    const discount = security.discountFromCoupon(basket.coupon ?? undefined)
    challengeUtils.solveIf(challenges.forgedCouponChallenge, () => { return (discount ?? 0) >= 80 })
    console.log(discount)
    return discount
  } else if (req.body.couponData) {
    const couponData = Buffer.from(req.body.couponData, 'base64').toString().split('-')
    const couponCode = String(couponData[0] ?? '')
    const couponDate = Number(couponData[1])
    // Whitelist coupon codes to avoid dynamic key lookups from user input
    const allowedCodes = new Set(Object.keys(campaigns))
    if (!allowedCodes.has(couponCode)) {
      return 0
    }
    const campaign = campaigns[couponCode as keyof typeof campaigns]

    if (campaign && couponDate == campaign.validOn) { // eslint-disable-line eqeqeq
      challengeUtils.solveIf(challenges.manipulateClockChallenge, () => { return campaign.validOn < new Date().getTime() })
      return campaign.discount
    }
  }
  return 0
}

const campaigns = {
  WMNSDY2019: { validOn: new Date('Mar 08, 2019 00:00:00 GMT+0100').getTime(), discount: 75 },
  WMNSDY2020: { validOn: new Date('Mar 08, 2020 00:00:00 GMT+0100').getTime(), discount: 60 },
  WMNSDY2021: { validOn: new Date('Mar 08, 2021 00:00:00 GMT+0100').getTime(), discount: 60 },
  WMNSDY2022: { validOn: new Date('Mar 08, 2022 00:00:00 GMT+0100').getTime(), discount: 60 },
  WMNSDY2023: { validOn: new Date('Mar 08, 2023 00:00:00 GMT+0100').getTime(), discount: 60 },
  ORANGE2020: { validOn: new Date('May 04, 2020 00:00:00 GMT+0100').getTime(), discount: 50 },
  ORANGE2021: { validOn: new Date('May 04, 2021 00:00:00 GMT+0100').getTime(), discount: 40 },
  ORANGE2022: { validOn: new Date('May 04, 2022 00:00:00 GMT+0100').getTime(), discount: 40 },
  ORANGE2023: { validOn: new Date('May 04, 2023 00:00:00 GMT+0100').getTime(), discount: 40 }
}
