/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// @ts-expect-error FIXME due to non-existing type definitions for MarsDB
import * as MarsDB from 'marsdb'

export const reviewsCollection = new MarsDB.Collection('posts')
export const ordersCollection = new MarsDB.Collection('orders')

// Insert helper with strict key validation to mitigate NoSQL operator injection
export const insertSafeOrder = async (order: {
	promotionalAmount: string
	paymentId: 'wallet' | 'card' | null
	addressId: number | null
	orderId: string
	delivered: boolean
	email?: string
	totalPrice: number
	products: Array<{ quantity: number, id: number | null, name: string, price: number, total: number, bonus: number }>
	bonus: number
	deliveryPrice: number
	eta: string
}) => {
	const hasNoSqlOperators = (val: unknown): boolean => {
		if (typeof val === 'string') return val.includes('$') || val.includes('.')
		if (Array.isArray(val)) return val.some(v => hasNoSqlOperators(v))
		if (val && typeof val === 'object') {
			return Object.keys(val as Record<string, unknown>).some(k => k.includes('$') || k.includes('.')) ||
				Object.values(val as Record<string, unknown>).some(v => hasNoSqlOperators(v))
		}
		return false
	}

	const allowedKeys = new Set([
		'promotionalAmount', 'paymentId', 'addressId', 'orderId', 'delivered', 'email', 'totalPrice', 'products', 'bonus', 'deliveryPrice', 'eta'
	])
	for (const key of Object.keys(order)) {
		if (!allowedKeys.has(key)) {
			throw new Error('Unexpected field in order payload')
		}
	}
	if (hasNoSqlOperators(order)) {
		throw new Error('Invalid characters in order payload')
	}
	return await ordersCollection.insert(order)
}
