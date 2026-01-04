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

	// Rebuild a strict, prototype-free document from validated inputs
	const safeProducts = order.products.map(p => ({
		quantity: Number.isInteger(p.quantity) ? p.quantity : 0,
		id: typeof p.id === 'number' ? p.id : null,
		name: String(p.name),
		price: Number.isFinite(p.price) ? p.price : 0,
		total: Number.isFinite(p.total) ? p.total : 0,
		bonus: Number.isFinite(p.bonus) ? p.bonus : 0
	}))

	const safeOrder = Object.assign(Object.create(null), {
		promotionalAmount: String(order.promotionalAmount),
		paymentId: (order.paymentId === 'wallet' || order.paymentId === 'card') ? order.paymentId : null,
		addressId: Number.isInteger(order.addressId) ? order.addressId : null,
		orderId: String(order.orderId),
		delivered: Boolean(order.delivered),
		email: typeof order.email === 'string' ? order.email : undefined,
		totalPrice: Number.isFinite(order.totalPrice) ? order.totalPrice : 0,
		products: safeProducts,
		bonus: Number.isFinite(order.bonus) ? order.bonus : 0,
		deliveryPrice: Number.isFinite(order.deliveryPrice) ? order.deliveryPrice : 0,
		eta: String(order.eta)
	})

	return await ordersCollection.insert(Object.freeze(safeOrder))
}
