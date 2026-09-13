// node scripts/test_operation_client.js -- no browser or device changes.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync('oltmanager/templates/oltmanager/_operation_client.html', 'utf8')
    .match(/<script>([\s\S]*?)<\/script>/)[1];
async function scenario(responses, expected, options = {}) {
    let count = 0, concurrent = 0, maximum = 0;
    const window = { addEventListener() {} };
    const context = { window, document: { querySelector: () => null }, AbortController,
        setTimeout, clearTimeout, Date, Set,
        fetch: async () => {
            concurrent++; maximum = Math.max(maximum, concurrent); count++;
            await new Promise(resolve => setTimeout(resolve, 2));
            concurrent--;
            const response = responses[Math.min(count - 1, responses.length - 1)];
            return { ok: true, status: 200, ...response,
                json: async () => { if (response.invalid) throw new SyntaxError('HTML'); return response.data; } };
        } };
    vm.runInNewContext(source, context);
    let completions = 0;
    await new Promise((resolve, reject) => {
        window.OptiVerseOperation.poll('/progress/', {
            intervalMs: 1, ...options,
            onDone: data => { completions++; try { assert.equal(expected, 'done'); assert.equal(typeof data.ok, 'boolean'); resolve(); } catch (e) { reject(e); } },
            onError: message => { completions++; try { assert.equal(expected, 'error'); assert.ok(message); resolve(); } catch (e) { reject(e); } }
        });
    });
    const finalCount = count;
    await new Promise(resolve => setTimeout(resolve, 10));
    assert.equal(count, finalCount, 'must stop polling after completion');
    assert.equal(maximum, 1, 'poll requests must not overlap');
    assert.equal(completions, 1);
    return count;
}
(async () => {
    await scenario([{ data: { done: false } }, { data: { done: true, ok: true } }], 'done');
    await scenario([{ data: { done: true, ok: false } }], 'done');
    assert.equal(await scenario([{ invalid: true }], 'error'), 15);
    assert.equal(await scenario([{ redirected: true }], 'error'), 1);
    await scenario([{ data: { done: false } }], 'error', { timeoutMs: 5 });
    console.log('PASS: success, failure, invalid JSON, login expiry, deadline and serialized polling.');
})().catch(error => { console.error(error); process.exitCode = 1; });
