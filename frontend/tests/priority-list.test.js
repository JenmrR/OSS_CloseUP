import test from 'node:test'
import assert from 'node:assert/strict'
import { priorityList } from '../src/display.js'
test('priority groups use stored grades and rank, not severity', () => {
 const rows=[{finding_id:'a',priority:'P1',priority_rank:3,severity:'CRITICAL'}, {finding_id:'b',priority:'P0',priority_rank:0,severity:'LOW'}, {finding_id:'c',priority:'P1',priority_rank:1}, {finding_id:'d',severity:'CRITICAL'}]
 assert.deepEqual(priorityList(rows).map(x=>x.finding_id),['b','c','a','d'])
 assert.deepEqual(priorityList(rows,'P1').map(x=>x.finding_id),['c','a'])
 assert.deepEqual(priorityList(rows,'unranked').map(x=>x.finding_id),['d'])
 assert.deepEqual(priorityList(rows,'all','original'),rows)
 assert.equal(rows[0].finding_id,'a')
})
