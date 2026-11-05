const { createHmac } = require('node:crypto');
function createLimiter(Model, secret, now = Date.now) {
  return async (scope, identity, limit, windowMs) => {
    const bucket = Math.floor(now() / windowMs);
    const digest = createHmac('sha256', secret).update(`${scope}:${identity}:${bucket}`).digest('hex');
    const update = { $inc: { count: 1 }, $setOnInsert: { expiresAt: new Date((bucket + 2) * windowMs) } };
    let record;
    try {
      record = await Model.findOneAndUpdate({ _id: digest }, update, { upsert: true, new: true });
    } catch (err) {
      if (err.code !== 11000) throw err;
      record = await Model.findOneAndUpdate({ _id: digest }, { $inc: { count: 1 } }, { new: true });
    }
    return !!record && record.count <= limit;
  };
}
module.exports = { createLimiter };
